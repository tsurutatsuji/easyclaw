const express = require("express");
const { execSync, spawn } = require("child_process");
const http = require("http");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const os = require("os");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const WebSocket = require("ws");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.get("/", (req, res) => { res.sendFile(path.join(__dirname, "public", "lp.html")); });

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-here";
const OPENCLAW_GATEWAY_PORT = 18789;

// --- JWT認証ミドルウェア ---
function auth(req, res, next) {
  const t = req.headers.authorization;
  if (!t) return res.status(401).json({ error: "ログイン必須" });
  try {
    req.user = jwt.verify(t.replace("Bearer ", ""), JWT_SECRET);
    next();
  } catch(e) {
    res.status(401).json({ error: "再ログインしてください" });
  }
}

// --- Database ---
const db = new Database(path.join(__dirname, "users.db"));
db.exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, createdAt TEXT)");
db.exec("CREATE TABLE IF NOT EXISTS otp_codes (id INTEGER PRIMARY KEY, email TEXT, code TEXT, expiresAt TEXT, used INTEGER DEFAULT 0)");
try { db.exec("ALTER TABLE users ADD COLUMN emailVerified INTEGER DEFAULT 0"); } catch(e) {}

db.exec(`CREATE TABLE IF NOT EXISTS user_settings (
  id INTEGER PRIMARY KEY,
  email TEXT UNIQUE,
  userId TEXT,
  provider TEXT DEFAULT 'ollama',
  ollamaUrl TEXT DEFAULT 'http://localhost:11434',
  model TEXT DEFAULT 'deepseek-r1:14b',
  apiKey TEXT,
  setupCompleted INTEGER DEFAULT 0,
  createdAt TEXT,
  updatedAt TEXT
)`);
db.exec(`CREATE TABLE IF NOT EXISTS chat_sessions (
  id INTEGER PRIMARY KEY,
  email TEXT,
  sessionKey TEXT UNIQUE,
  title TEXT,
  createdAt TEXT,
  updatedAt TEXT
)`);
db.exec(`CREATE TABLE IF NOT EXISTS chat_messages (
  id INTEGER PRIMARY KEY,
  sessionKey TEXT,
  role TEXT,
  content TEXT,
  model TEXT,
  timestamp TEXT
)`);

function generateUserId(email) {
  return email.split("@")[0].replace(/[^a-zA-Z0-9]/g, "-").toLowerCase();
}

// --- Email/OTP ---
const transporter = nodemailer.createTransport({ service: "gmail", auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS } });

async function sendOTP(email) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  db.prepare("DELETE FROM otp_codes WHERE email=?").run(email);
  db.prepare("INSERT INTO otp_codes (email, code, expiresAt) VALUES (?,?,?)").run(email, code, expiresAt);
  if (process.env.GMAIL_USER && process.env.GMAIL_PASS) {
    await transporter.sendMail({
      from: '"EasyClaw" <' + process.env.GMAIL_USER + '>',
      to: email,
      subject: "【EasyClaw】認証コード: " + code,
      html: "<div style='font-family:sans-serif;max-width:400px;margin:0 auto;padding:32px;background:#1a1a2e;color:#fff;border-radius:12px'><h2 style='text-align:center;color:#ff5722'>EasyClaw</h2><p style='text-align:center'>あなたの認証コード:</p><div style='text-align:center;font-size:36px;font-weight:bold;letter-spacing:8px;padding:16px;background:#16213e;border-radius:8px;margin:16px 0'>" + code + "</div><p style='text-align:center;color:#999;font-size:12px'>このコードは10分間有効です</p></div>"
    });
  } else {
    console.log("\n========================================");
    console.log("  OTP for " + email + ": " + code);
    console.log("========================================\n");
  }
  return code;
}

// --- Auth Routes ---
app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "メールとパスワードを入力" });
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "正しいメールアドレスを入力してください" });
    if (password.length < 6) return res.status(400).json({ error: "パスワードは6文字以上" });
    const existing = db.prepare("SELECT * FROM users WHERE email=?").get(email);
    if (existing && existing.emailVerified) return res.status(400).json({ error: "登録済みメール" });
    if (existing && !existing.emailVerified) {
      db.prepare("UPDATE users SET password=? WHERE email=?").run(bcrypt.hashSync(password, 10), email);
    } else {
      db.prepare("INSERT INTO users (email, password, emailVerified, createdAt) VALUES (?,?,0,?)").run(email, bcrypt.hashSync(password, 10), new Date().toISOString());
    }
    const existingSettings = db.prepare("SELECT * FROM user_settings WHERE email=?").get(email);
    if (!existingSettings) {
      db.prepare("INSERT INTO user_settings (email, userId, createdAt) VALUES (?,?,?)").run(email, generateUserId(email), new Date().toISOString());
    }
    await sendOTP(email);
    res.json({ success: true, needVerify: true, email });
  } catch(e) {
    console.error("Register error:", e.message);
    res.status(500).json({ error: "登録に失敗しました" });
  }
});

app.post("/api/verify-otp", (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: "コードを入力してください" });
    const otp = db.prepare("SELECT * FROM otp_codes WHERE email=? AND code=? AND used=0").get(email, code);
    if (!otp) return res.status(400).json({ error: "認証コードが無効です" });
    if (new Date(otp.expiresAt) < new Date()) return res.status(400).json({ error: "認証コードの有効期限が切れました" });
    db.prepare("UPDATE otp_codes SET used=1 WHERE id=?").run(otp.id);
    db.prepare("UPDATE users SET emailVerified=1 WHERE email=?").run(email);
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ success: true, token, email });
  } catch(e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: "メールアドレスが必要です" });
    await sendOTP(email);
    res.json({ success: true });
  } catch(e) {
    res.status(500).json({ error: "送信失敗" });
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "メールとパスワードを入力" });
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "メールまたはパスワードが違います" });
  if (!user.emailVerified) {
    await sendOTP(email);
    return res.json({ success: true, needVerify: true, email });
  }
  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ success: true, token, email });
});

// --- Verify Token ---
app.get("/api/verify-token", auth, (req, res) => {
  const settings = db.prepare("SELECT * FROM user_settings WHERE email=?").get(req.user.email);
  res.json({ valid: true, email: req.user.email, setupCompleted: settings ? settings.setupCompleted : 0 });
});

// --- User Settings ---
app.get("/api/settings", auth, (req, res) => {
  let settings = db.prepare("SELECT * FROM user_settings WHERE email=?").get(req.user.email);
  if (!settings) {
    db.prepare("INSERT INTO user_settings (email, userId, createdAt) VALUES (?,?,?)").run(req.user.email, generateUserId(req.user.email), new Date().toISOString());
    settings = db.prepare("SELECT * FROM user_settings WHERE email=?").get(req.user.email);
  }
  res.json({ success: true, settings });
});

app.post("/api/settings", auth, (req, res) => {
  const { provider, ollamaUrl, model, apiKey } = req.body;
  const now = new Date().toISOString();
  const existing = db.prepare("SELECT * FROM user_settings WHERE email=?").get(req.user.email);
  if (existing) {
    db.prepare("UPDATE user_settings SET provider=?, ollamaUrl=?, model=?, apiKey=?, setupCompleted=1, updatedAt=? WHERE email=?")
      .run(provider || "ollama", ollamaUrl || "http://localhost:11434", model || "deepseek-r1:14b", apiKey || null, now, req.user.email);
  } else {
    db.prepare("INSERT INTO user_settings (email, userId, provider, ollamaUrl, model, apiKey, setupCompleted, createdAt, updatedAt) VALUES (?,?,?,?,?,?,1,?,?)")
      .run(req.user.email, generateUserId(req.user.email), provider || "ollama", ollamaUrl || "http://localhost:11434", model || "deepseek-r1:14b", apiKey || null, now, now);
  }
  res.json({ success: true });
});

// --- Ollama Proxy ---
function ollamaRequest(ollamaUrl, apiPath, method, body) {
  return new Promise((resolve, reject) => {
    const url = new URL(apiPath, ollamaUrl);
    const options = { hostname: url.hostname, port: url.port, path: url.pathname, method, headers: { "Content-Type": "application/json" } };
    const req = http.request(options, (resp) => {
      let data = "";
      resp.on("data", (chunk) => { data += chunk; });
      resp.on("end", () => { try { resolve({ status: resp.statusCode, data: JSON.parse(data) }); } catch(e) { resolve({ status: resp.statusCode, data: data }); } });
    });
    req.on("error", (e) => reject(e));
    req.setTimeout(10000, () => { req.destroy(); reject(new Error("timeout")); });
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

app.get("/api/ollama/models", auth, async (req, res) => {
  try {
    const settings = db.prepare("SELECT ollamaUrl FROM user_settings WHERE email=?").get(req.user.email);
    const ollamaUrl = (settings && settings.ollamaUrl) || "http://localhost:11434";
    const result = await ollamaRequest(ollamaUrl, "/api/tags", "GET");
    res.json({ success: true, models: result.data.models || [] });
  } catch(e) { res.json({ success: false, error: "Ollamaに接続できません: " + e.message, models: [] }); }
});

app.get("/api/ollama/health", auth, async (req, res) => {
  try {
    const settings = db.prepare("SELECT ollamaUrl FROM user_settings WHERE email=?").get(req.user.email);
    const ollamaUrl = (settings && settings.ollamaUrl) || "http://localhost:11434";
    const result = await ollamaRequest(ollamaUrl, "/api/tags", "GET");
    res.json({ ok: result.status === 200 });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post("/api/ollama/chat", auth, async (req, res) => {
  try {
    const settings = db.prepare("SELECT * FROM user_settings WHERE email=?").get(req.user.email);
    const ollamaUrl = (settings && settings.ollamaUrl) || "http://localhost:11434";
    const model = req.body.model || (settings && settings.model) || "deepseek-r1:14b";
    const rawMessages = req.body.messages || [];
    const systemMsg = { role: "system", content: "You are EasyClaw AI assistant. IMPORTANT: You MUST always respond in Japanese (日本語). Never respond in English or Chinese. All your responses must be written entirely in Japanese. あなたはEasyClawのAIアシスタントです。全ての回答を必ず日本語で行ってください。英語や中国語で回答してはいけません。" };
    const messages = [systemMsg, ...rawMessages];
    const url = new URL("/api/chat", ollamaUrl);
    const options = { hostname: url.hostname, port: url.port, path: url.pathname, method: "POST", headers: { "Content-Type": "application/json" } };
    const ollamaReq = http.request(options, (ollamaRes) => {
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");
      ollamaRes.on("data", (chunk) => {
        const lines = chunk.toString().split("\n").filter(l => l.trim());
        for (const line of lines) {
          try {
            const parsed = JSON.parse(line);
            res.write("data: " + JSON.stringify(parsed) + "\n\n");
            if (parsed.done) { res.write("data: [DONE]\n\n"); res.end(); }
          } catch(e) {}
        }
      });
      ollamaRes.on("end", () => { if (!res.writableEnded) { res.write("data: [DONE]\n\n"); res.end(); } });
      ollamaRes.on("error", () => { if (!res.writableEnded) res.end(); });
    });
    ollamaReq.on("error", (e) => { res.status(502).json({ error: "Ollama接続エラー: " + e.message }); });
    ollamaReq.write(JSON.stringify({ model, messages, stream: true, keep_alive: "30m" }));
    ollamaReq.end();
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// =============================================
// OpenClaw Gateway Management
// =============================================
let gatewayProcess = null;
let gatewayWs = null;       // Persistent WebSocket connection pool
let gatewayReady = false;   // Is gateway WS connected?

// Resolve openclaw binary path for Windows (npm global .cmd wrapper)
const OPENCLAW_BIN = process.platform === "win32"
  ? path.join(process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming"), "npm", "openclaw.cmd")
  : "openclaw";

function getOpenClawConfigPath() {
  return path.join(os.homedir(), ".openclaw", "openclaw.json");
}

// --- Persistent WebSocket to Gateway ---
function connectGatewayWs() {
  if (gatewayWs && gatewayWs.readyState === WebSocket.OPEN) return;
  try {
    gatewayWs = new WebSocket("ws://127.0.0.1:" + OPENCLAW_GATEWAY_PORT);
    gatewayWs.on("open", () => { gatewayReady = true; console.log("[Gateway WS] Connected (persistent)"); });
    gatewayWs.on("close", () => {
      gatewayReady = false;
      gatewayWs = null;
      // Auto-reconnect if gateway process is still alive
      if (gatewayProcess && !gatewayProcess.killed) {
        setTimeout(connectGatewayWs, 2000);
      }
    });
    gatewayWs.on("error", () => { gatewayReady = false; gatewayWs = null; });
  } catch(e) { gatewayReady = false; }
}

// --- Auto-start Gateway on server boot ---
function autoStartGateway() {
  const configPath = getOpenClawConfigPath();
  if (!fs.existsSync(configPath)) {
    console.log("[Gateway] No config found at", configPath, "— skipping auto-start");
    console.log("[Gateway] Run setup to configure OpenClaw first");
    return;
  }
  if (gatewayProcess && !gatewayProcess.killed) return;

  console.log("[Gateway] Auto-starting OpenClaw Gateway...");
  console.log("[Gateway] Using binary:", OPENCLAW_BIN);
  gatewayProcess = spawn(OPENCLAW_BIN, ["gateway", "--port", String(OPENCLAW_GATEWAY_PORT)], {
    stdio: ["ignore", "pipe", "pipe"],
    shell: true,
    env: { ...process.env, OPENCLAW_CONFIG_PATH: configPath }
  });

  gatewayProcess.stdout.on("data", (data) => {
    console.log("[OpenClaw Gateway]", data.toString().trim());
  });
  gatewayProcess.stderr.on("data", (data) => {
    console.error("[OpenClaw Gateway ERROR]", data.toString().trim());
  });
  gatewayProcess.on("close", (code) => {
    console.log("[OpenClaw Gateway] Process exited with code", code);
    gatewayProcess = null;
    gatewayReady = false;
  });
  gatewayProcess.on("error", (err) => {
    console.error("[OpenClaw Gateway] Failed to start:", err.message);
    gatewayProcess = null;
  });

  // Connect persistent WS after brief startup delay
  setTimeout(connectGatewayWs, 3000);
}

// --- Prerequisites Check ---
app.get("/api/prerequisites", (req, res) => {
  const result = { node: { installed: false, version: null, ok: false }, ollama: { installed: false, version: null, ok: false }, openclaw: { installed: false, version: null, ok: false } };

  // Node.js
  try {
    const v = process.version; // e.g. "v22.11.0"
    result.node.installed = true;
    result.node.version = v;
    const major = parseInt(v.replace("v", "").split(".")[0], 10);
    result.node.ok = major >= 22;
  } catch(e) {}

  // Ollama
  try {
    const v = execSync("ollama --version 2>&1", { timeout: 5000 }).toString().trim();
    result.ollama.installed = true;
    result.ollama.version = v;
    result.ollama.ok = true;
  } catch(e) {}

  // OpenClaw CLI
  try {
    const raw = execSync("openclaw --version 2>&1", { timeout: 5000 }).toString().trim();
    result.openclaw.installed = true;
    // Extract version number from output (may include config warnings)
    const versionMatch = raw.match(/(\d+\.\d+[\.\d-]*)/);
    result.openclaw.version = versionMatch ? versionMatch[1] : raw.split("\n").pop().trim();
    result.openclaw.ok = true;
  } catch(e) {}

  res.json(result);
});

// --- Gateway Status ---
app.get("/api/openclaw/status", (req, res) => {
  const running = !!(gatewayProcess && !gatewayProcess.killed);
  res.json({ running, connected: running && gatewayReady });
});

// --- Start Gateway (manual / after setup) ---
app.post("/api/openclaw/start", auth, (req, res) => {
  if (gatewayProcess && !gatewayProcess.killed) {
    return res.json({ success: true, message: "Gateway is already running" });
  }
  autoStartGateway();
  setTimeout(() => {
    if (gatewayProcess && !gatewayProcess.killed) {
      res.json({ success: true, message: "Gateway started", port: OPENCLAW_GATEWAY_PORT });
    } else {
      res.status(500).json({ success: false, error: "Gatewayの起動に失敗しました" });
    }
  }, 2000);
});

// --- Stop Gateway ---
app.post("/api/openclaw/stop", auth, (req, res) => {
  if (gatewayProcess && !gatewayProcess.killed) {
    gatewayProcess.kill("SIGTERM");
    gatewayProcess = null;
    res.json({ success: true, message: "Gateway stopped" });
  } else {
    res.json({ success: true, message: "Gateway is not running" });
  }
});

// --- Configure OpenClaw ---
app.post("/api/openclaw/configure", auth, (req, res) => {
  try {
    const { ollamaUrl, model } = req.body;
    const configDir = path.join(os.homedir(), ".openclaw");
    const configPath = path.join(configDir, "openclaw.json");

    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }

    // Load existing config and merge (preserve user's other settings)
    let config = {};
    if (fs.existsSync(configPath)) {
      try { config = JSON.parse(fs.readFileSync(configPath, "utf8")); } catch(e) {}
    }

    const modelName = model || "deepseek-r1:14b";
    const baseUrl = (ollamaUrl || "http://127.0.0.1:11434").replace(/\/$/, "");

    // Update model provider
    if (!config.models) config.models = {};
    if (!config.models.providers) config.models.providers = {};
    config.models.providers.ollama = {
      apiKey: "ollama-local",
      baseUrl: baseUrl + "/v1",
      models: [{
        id: modelName, name: modelName, contextWindow: 2048,
        input: ["text"], reasoning: false,
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 }
      }]
    };

    // Update default agent model
    if (!config.agents) config.agents = {};
    if (!config.agents.defaults) config.agents.defaults = {};
    config.agents.defaults.model = { primary: "ollama/" + modelName };

    // Ensure gateway config
    if (!config.gateway) config.gateway = {};
    config.gateway.port = OPENCLAW_GATEWAY_PORT;
    config.gateway.mode = "local";
    config.gateway.bind = "loopback";

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
    res.json({ success: true, configPath });
  } catch(e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// =============================================
// OpenClaw Browser Agent Management
// =============================================
let browserRunning = false;

// Read gateway token from openclaw config for browser commands
function getGatewayToken() {
  try {
    const configPath = path.join(os.homedir(), ".openclaw", "openclaw.json");
    const config = JSON.parse(fs.readFileSync(configPath, "utf8"));
    return (config.gateway && config.gateway.auth && config.gateway.auth.token) || "";
  } catch(e) { return ""; }
}

const BROWSER_PROFILE = "openclaw";

function execBrowser(args, timeoutMs = 30000) {
  const token = getGatewayToken();
  const tokenFlag = token ? ' --token "' + token + '"' : "";
  const cmd = '"' + OPENCLAW_BIN + '" browser ' + args + ' --browser-profile ' + BROWSER_PROFILE + tokenFlag;
  const result = execSync(cmd, {
    timeout: timeoutMs,
    shell: true,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"]
  });
  const cleaned = result.replace(/\x1B\[[0-9;]*m/g, "").trim();
  // Try to extract JSON from output
  const jsonMatch = cleaned.match(/(\{[\s\S]*\}|\[[\s\S]*\])/);
  if (jsonMatch) {
    try { return JSON.parse(jsonMatch[0]); } catch(e) {}
  }
  return cleaned;
}

async function ensureBrowserRunning() {
  try {
    const status = execBrowser("status --json");
    if (status && status.running && status.cdpReady) {
      browserRunning = true;
      return true;
    }
  } catch(e) { /* not running */ }

  try {
    execBrowser("start", 20000);
    // Wait for CDP to be ready
    for (let i = 0; i < 10; i++) {
      await new Promise(r => setTimeout(r, 1500));
      try {
        const status = execBrowser("status --json");
        if (status && status.running && status.cdpReady) {
          browserRunning = true;
          console.log("[Browser] Started successfully (profile: " + BROWSER_PROFILE + ")");
          return true;
        }
      } catch(e) {}
    }
  } catch(e) {
    console.error("[Browser] Failed to start:", e.message);
  }
  return false;
}

// =============================================
// LLM Orchestrator — Auto-select best model per task
// =============================================
const ORCHESTRATOR_MODELS = {
  agent: "qwen2.5-coder:7b",
  coding: "qwen2.5-coder:7b",
  reasoning: "deepseek-r1:14b",
  chat: "llama3.2",
  browser: "deepseek-r1:14b"
};

const CODE_KEYWORDS = [
  // Programming languages
  "python", "javascript", "typescript", "java", "c++", "c#", "rust", "go", "ruby", "php", "swift", "kotlin", "html", "css", "sql", "bash", "shell",
  // JP coding terms
  "コード", "プログラム", "プログラミング", "関数", "変数", "クラス", "メソッド", "バグ", "デバッグ", "エラー", "コンパイル", "ビルド", "デプロイ",
  "アルゴリズム", "ソート", "配列", "ループ", "条件分岐", "API", "データベース", "サーバー", "フロントエンド", "バックエンド",
  "リファクタリング", "テスト", "ユニットテスト", "スクリプト", "ライブラリ", "フレームワーク", "パッケージ",
  // EN coding terms
  "code", "function", "variable", "class", "method", "debug", "error", "compile", "build", "deploy",
  "algorithm", "array", "loop", "database", "server", "frontend", "backend", "refactor", "test", "script",
  "import", "export", "npm", "git", "docker", "react", "vue", "node", "express",
  // Code patterns
  "```", "def ", "function ", "const ", "let ", "var ", "class ", "import ", "from ", "require(",
];

const REASONING_KEYWORDS = [
  // JP reasoning terms
  "なぜ", "どうして", "理由", "分析", "比較", "評価", "考察", "検討", "戦略", "計画",
  "メリット", "デメリット", "長所", "短所", "違い", "論理", "議論", "意見",
  "要約", "まとめ", "レポート", "解説", "詳しく", "深く",
  "数学", "計算", "証明", "確率", "統計", "方程式",
  // EN reasoning terms
  "why", "because", "reason", "analyze", "compare", "evaluate", "strategy", "plan",
  "pros and cons", "difference", "explain", "summarize", "report", "math", "calculate",
];

const BROWSER_KEYWORDS = [
  // JP browser terms
  "ブラウザ", "ウェブサイト", "サイト", "ページ", "開いて", "見て", "検索して",
  "クリック", "入力して", "フォーム", "ログイン", "スクレイピング", "ウェブ",
  "ホームページ", "アクセスして", "表示して",
  // EN browser terms
  "browse", "website", "web page", "open", "visit", "click", "navigate",
  "scrape", "fill form", "login to", "sign in", "search on",
];

const AGENT_KEYWORDS = [
  // JP action verbs — user wants something DONE
  "作って", "作成", "作る", "ビルド", "構築", "生成", "実装", "開発",
  "修正", "直して", "修正して", "フィックス", "変更", "変えて", "更新",
  "追加", "追加して", "削除", "削除して", "インストール", "セットアップ",
  "ファイル", "プロジェクト", "アプリ", "アプリケーション", "ツール",
  "書いて", "書き換え", "リネーム", "移動", "コピー",
  "実行して", "走らせて", "テストして", "起動して",
  // EN action verbs
  "create", "build", "make", "generate", "implement", "develop",
  "fix", "change", "update", "modify", "add", "remove", "delete",
  "install", "setup", "write", "rename", "move", "copy",
  "run", "execute", "test", "start", "deploy",
  "file", "project", "app", "tool",
];

function classifyTask(message) {
  const lower = message.toLowerCase();

  // Score each category
  let codeScore = 0;
  let reasonScore = 0;
  let browserScore = 0;
  let agentScore = 0;

  for (const kw of BROWSER_KEYWORDS) {
    if (lower.includes(kw.toLowerCase())) browserScore++;
  }
  if (/https?:\/\/\S+/.test(message) || /www\.\S+/.test(message)) browserScore += 5;

  for (const kw of CODE_KEYWORDS) {
    if (lower.includes(kw.toLowerCase())) codeScore++;
  }
  for (const kw of REASONING_KEYWORDS) {
    if (lower.includes(kw.toLowerCase())) reasonScore++;
  }
  for (const kw of AGENT_KEYWORDS) {
    if (lower.includes(kw.toLowerCase())) agentScore++;
  }

  // Code patterns boost
  if (/```/.test(message)) codeScore += 3;
  if (/\b(def|function|class|const|let|var|import|require)\b/.test(lower)) codeScore += 2;
  if (/[{}();=]/.test(message) && message.length > 20) codeScore += 1;

  // Agent boost: code + action = agent (user wants something BUILT, not discussed)
  if (codeScore >= 1 && agentScore >= 1) agentScore += 3;
  if (agentScore >= 2 && codeScore >= 1) agentScore += 2;

  // Decision — browser first, then agent, then code, then reasoning
  if (browserScore >= 3) return "browser";
  if (agentScore >= 3) return "agent";
  if (codeScore >= 2) return "coding";
  if (reasonScore >= 2) return "reasoning";
  if (message.length > 100 && reasonScore >= 1) return "reasoning";
  return "chat";
}

function getOrchestratedModel(message, userModel) {
  // If user explicitly picked "auto" or default, use orchestration
  // If user explicitly selected a specific model, respect that
  const autoModels = ["deepseek-r1:14b", "auto", ""];
  if (userModel && !autoModels.includes(userModel)) {
    return { model: userModel, category: "manual", reason: "ユーザー指定" };
  }

  const category = classifyTask(message);
  const model = ORCHESTRATOR_MODELS[category];
  const reasons = {
    agent: "コーディングエージェント",
    coding: "コード生成に最適化",
    reasoning: "深い推論・分析に最適化",
    chat: "高速レスポンス",
    browser: "ブラウザエージェント"
  };
  return { model, category, reason: reasons[category] };
}

// =============================================
// Local Chat (with OpenClaw Gateway relay)
// =============================================

// Send message — tries OpenClaw Gateway first, falls back to direct Ollama
app.post("/api/local/chat/send", auth, async (req, res) => {
  try {
    const { message, sessionKey: reqSessionKey, model: reqModel } = req.body;
    if (!message) return res.status(400).json({ error: "メッセージが必要です" });
    const settings = db.prepare("SELECT * FROM user_settings WHERE email=?").get(req.user.email);
    const ollamaUrl = (settings && settings.ollamaUrl) || "http://localhost:11434";

    // Orchestrate: auto-select best model for this task
    const userModel = reqModel || (settings && settings.model) || "deepseek-r1:14b";
    const orchestrated = getOrchestratedModel(message, userModel);
    const model = orchestrated.model;
    console.log("[Orchestrator]", orchestrated.category, "→", model, "(" + orchestrated.reason + ")");
    const sessionKey = reqSessionKey || "session-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8);
    const now = new Date().toISOString();

    // Create/update session
    const existingSession = db.prepare("SELECT * FROM chat_sessions WHERE sessionKey=?").get(sessionKey);
    if (!existingSession) {
      const title = message.length > 30 ? message.slice(0, 30) + "..." : message;
      db.prepare("INSERT INTO chat_sessions (email, sessionKey, title, createdAt, updatedAt) VALUES (?,?,?,?,?)").run(req.user.email, sessionKey, title, now, now);
    } else {
      db.prepare("UPDATE chat_sessions SET updatedAt=? WHERE sessionKey=?").run(now, sessionKey);
    }

    // Save user message
    db.prepare("INSERT INTO chat_messages (sessionKey, role, content, model, timestamp) VALUES (?,?,?,?,?)").run(sessionKey, "user", message, model, now);

    // SSE headers
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.write("data: " + JSON.stringify({ sessionKey, orchestrator: { model: orchestrated.model, category: orchestrated.category, reason: orchestrated.reason } }) + "\n\n");

    // Route browser tasks to agent loop
    if (orchestrated.category === "browser") {
      try {
        await runBrowserAgent(message, sessionKey, model, ollamaUrl, res);
        return;
      } catch(e) {
        console.error("[Browser Agent] Error:", e.message);
        if (!res.writableEnded) {
          res.write("data: " + JSON.stringify({ error: "ブラウザエージェントエラー: " + e.message }) + "\n\n");
          res.write("data: " + JSON.stringify({ done: true, sessionKey }) + "\n\n");
          res.end();
        }
        return;
      }
    }

    // Route coding agent tasks
    if (orchestrated.category === "agent") {
      try {
        await runCodingAgent(message, sessionKey, model, ollamaUrl, res);
        return;
      } catch(e) {
        console.error("[Coding Agent] Error:", e.message);
        if (!res.writableEnded) {
          res.write("data: " + JSON.stringify({ error: "エージェントエラー: " + e.message }) + "\n\n");
          res.write("data: " + JSON.stringify({ done: true, sessionKey }) + "\n\n");
          res.end();
        }
        return;
      }
    }

    // Try OpenClaw Gateway relay (only if persistent WS is connected)
    if (gatewayReady && gatewayProcess && !gatewayProcess.killed) {
      try {
        await sendViaGateway(message, sessionKey, model, res);
        return;
      } catch(gwErr) {
        console.log("[Chat] Gateway relay failed, falling back to direct Ollama:", gwErr.message);
      }
    }

    // Fallback: Direct Ollama
    await sendViaOllama(sessionKey, model, ollamaUrl, res);
  } catch(e) {
    if (!res.headersSent) {
      res.status(500).json({ error: e.message });
    } else if (!res.writableEnded) {
      res.write("data: " + JSON.stringify({ error: e.message }) + "\n\n");
      res.end();
    }
  }
});

// Send via OpenClaw Gateway WebSocket
function sendViaGateway(message, sessionKey, model, res) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket("ws://127.0.0.1:" + OPENCLAW_GATEWAY_PORT);
    let fullResponse = "";
    let resolved = false;
    const timeout = setTimeout(() => {
      if (!resolved) { resolved = true; ws.close(); reject(new Error("Gateway timeout")); }
    }, 120000);

    ws.on("open", () => {
      ws.send(JSON.stringify({ type: "chat", payload: { text: message, sessionKey: sessionKey, systemPrompt: "あなたはEasyClawのAIアシスタントです。必ず日本語で回答してください。丁寧で分かりやすい日本語を使ってください。" } }));
    });

    ws.on("message", (data) => {
      try {
        const msg = JSON.parse(data.toString());

        if (msg.type === "agent_activity" || msg.type === "tool_call") {
          // Relay agent activity to client
          res.write("data: " + JSON.stringify({ type: "agent_activity", tool: msg.payload && msg.payload.tool, status: msg.payload && msg.payload.status, params: msg.payload && msg.payload.params }) + "\n\n");
        } else if (msg.type === "chat_token" || msg.type === "token") {
          const content = (msg.payload && msg.payload.text) || (msg.payload && msg.payload.content) || "";
          fullResponse += content;
          res.write("data: " + JSON.stringify({ content, done: false }) + "\n\n");
        } else if (msg.type === "chat_done" || msg.type === "done") {
          // Save assistant message
          db.prepare("INSERT INTO chat_messages (sessionKey, role, content, model, timestamp) VALUES (?,?,?,?,?)")
            .run(sessionKey, "assistant", fullResponse, model, new Date().toISOString());
          res.write("data: " + JSON.stringify({ content: "", done: true, sessionKey }) + "\n\n");
          res.end();
          clearTimeout(timeout);
          resolved = true;
          ws.close();
          resolve();
        } else if (msg.type === "error") {
          clearTimeout(timeout);
          resolved = true;
          ws.close();
          reject(new Error((msg.payload && msg.payload.message) || "Gateway error"));
        }
      } catch(e) {
        // Non-JSON message, ignore
      }
    });

    ws.on("error", (err) => {
      if (!resolved) { clearTimeout(timeout); resolved = true; reject(err); }
    });

    ws.on("close", () => {
      if (!resolved) {
        clearTimeout(timeout);
        resolved = true;
        if (fullResponse) {
          db.prepare("INSERT INTO chat_messages (sessionKey, role, content, model, timestamp) VALUES (?,?,?,?,?)")
            .run(sessionKey, "assistant", fullResponse, model, new Date().toISOString());
          res.write("data: " + JSON.stringify({ done: true, sessionKey }) + "\n\n");
          res.end();
          resolve();
        } else {
          reject(new Error("Gateway connection closed"));
        }
      }
    });
  });
}

// Send via direct Ollama API (fallback)
function sendViaOllama(sessionKey, model, ollamaUrl, res) {
  return new Promise((resolve, reject) => {
    // Only send last 10 messages to reduce processing time
    const history = db.prepare("SELECT role, content FROM chat_messages WHERE sessionKey=? ORDER BY id DESC LIMIT 10").all(sessionKey).reverse();
    const messages = [
      { role: "system", content: "You are EasyClaw AI assistant. IMPORTANT: You MUST always respond in Japanese (日本語). Never respond in English or Chinese. All your responses must be written entirely in Japanese. あなたはEasyClawのAIアシスタントです。全ての回答を必ず日本語で行ってください。英語や中国語で回答してはいけません。" },
      ...history.map(m => ({ role: m.role, content: m.content }))
    ];

    const url = new URL("/api/chat", ollamaUrl);
    const options = { hostname: url.hostname, port: url.port, path: url.pathname, method: "POST", headers: { "Content-Type": "application/json" } };
    let fullResponse = "";

    const ollamaReq = http.request(options, (ollamaRes) => {
      ollamaRes.on("data", (chunk) => {
        const lines = chunk.toString().split("\n").filter(l => l.trim());
        for (const line of lines) {
          try {
            const parsed = JSON.parse(line);
            if (parsed.message && parsed.message.content) {
              fullResponse += parsed.message.content;
              res.write("data: " + JSON.stringify({ content: parsed.message.content, done: false }) + "\n\n");
            }
            if (parsed.done) {
              db.prepare("INSERT INTO chat_messages (sessionKey, role, content, model, timestamp) VALUES (?,?,?,?,?)")
                .run(sessionKey, "assistant", fullResponse, model, new Date().toISOString());
              res.write("data: " + JSON.stringify({ content: "", done: true, sessionKey }) + "\n\n");
              res.end();
              resolve();
            }
          } catch(e) {}
        }
      });
      ollamaRes.on("end", () => {
        if (!res.writableEnded) {
          if (fullResponse) {
            db.prepare("INSERT INTO chat_messages (sessionKey, role, content, model, timestamp) VALUES (?,?,?,?,?)")
              .run(sessionKey, "assistant", fullResponse, model, new Date().toISOString());
          }
          res.write("data: " + JSON.stringify({ done: true, sessionKey }) + "\n\n");
          res.end();
          resolve();
        }
      });
      ollamaRes.on("error", (e) => {
        res.write("data: " + JSON.stringify({ error: e.message }) + "\n\n");
        res.end();
        reject(e);
      });
    });

    ollamaReq.on("error", (e) => {
      res.write("data: " + JSON.stringify({ error: "Ollama接続エラー: " + e.message }) + "\n\n");
      res.end();
      reject(e);
    });
    ollamaReq.setTimeout(120000, () => { ollamaReq.destroy(); });
    ollamaReq.write(JSON.stringify({ model, messages, stream: true, keep_alive: "30m", options: { num_ctx: 2048 } }));
    ollamaReq.end();
  });
}

// =============================================
// Browser Agent — System Prompt & Helpers
// =============================================
const BROWSER_AGENT_SYSTEM_PROMPT = `You are EasyClaw Browser Agent. You control a real web browser to help the user.
You MUST always respond in Japanese (日本語) for explanations, but use English for action JSON.

## How you work
You receive a PAGE SNAPSHOT showing the current page state with numbered element refs.
You analyze it and decide what to do next.

## Output Format
You MUST output EXACTLY ONE action per turn as a JSON code block, followed by a brief Japanese explanation.

\`\`\`action
{"action": "navigate", "url": "https://example.com"}
\`\`\`
URLに移動します。

## Available Actions
- {"action": "navigate", "url": "<url>"} — Navigate to a URL
- {"action": "click", "ref": "<number>"} — Click element by ref number
- {"action": "type", "ref": "<number>", "text": "<text>"} — Type text into element
- {"action": "type", "ref": "<number>", "text": "<text>", "submit": true} — Type and press Enter
- {"action": "scroll", "direction": "down"|"up"} — Scroll the page
- {"action": "wait", "seconds": 2} — Wait for page to load
- {"action": "done", "summary": "<結果の要約>"} — Task is complete, report results

## Rules
- ALWAYS output exactly one action JSON block per turn
- Use "done" when the task is complete or you have gathered the requested information
- Include a short Japanese explanation after the action block
- If a page shows an error or unexpected state, try an alternative approach
- Never enter passwords, credit card numbers, or sensitive data
- IMPORTANT: The ref numbers come from the snapshot — always use the CURRENT snapshot's refs

あなたはEasyClawブラウザエージェントです。ウェブブラウザを操作してユーザーを支援します。
アクションは必ず上記のJSON形式で出力してください。説明は日本語で書いてください。`;

// Emit SSE agent_activity event
function emitActivity(res, tool, status, params) {
  if (res.writableEnded) return;
  res.write("data: " + JSON.stringify({ type: "agent_activity", tool, status, params }) + "\n\n");
}

// Parse action JSON from LLM response
function parseAction(text) {
  const match = text.match(/```action\s*\n([\s\S]*?)```/);
  if (match) {
    try { return JSON.parse(match[1].trim()); } catch(e) {}
  }
  const jsonMatch = text.match(/\{[^{}]*"action"\s*:\s*"[^"]+?"[^{}]*\}/);
  if (jsonMatch) {
    try { return JSON.parse(jsonMatch[0]); } catch(e) {}
  }
  return null;
}

// Execute a browser action via CLI
function executeAction(action) {
  switch (action.action) {
    case "navigate":
      execBrowser('navigate "' + action.url.replace(/"/g, '\\"') + '"');
      break;
    case "click":
      execBrowser("click " + action.ref + (action.double ? " --double" : ""));
      break;
    case "type": {
      const submitFlag = action.submit ? " --submit" : "";
      execBrowser('type ' + action.ref + ' "' + action.text.replace(/"/g, '\\"') + '"' + submitFlag);
      break;
    }
    case "scroll": {
      const dir = action.direction === "up" ? "-500" : "500";
      execBrowser("evaluate --fn \"window.scrollBy(0, " + dir + ")\"");
      break;
    }
    case "wait": {
      const secs = Math.min(action.seconds || 2, 10);
      execBrowser('wait --text "." --timeout ' + (secs * 1000), secs * 1000 + 5000);
      break;
    }
    default:
      throw new Error("Unknown action: " + action.action);
  }
}

// Human-readable action description
function actionDescription(action) {
  switch (action.action) {
    case "navigate": return action.url;
    case "click": return "要素 #" + action.ref + " をクリック";
    case "type": return "テキスト入力: " + (action.text || "").slice(0, 40);
    case "scroll": return (action.direction === "up" ? "上" : "下") + "にスクロール";
    case "wait": return (action.seconds || 2) + "秒待機";
    default: return action.action;
  }
}

// Call Ollama (non-streaming) for agent loop
function callOllamaSync(ollamaUrl, model, messages, opts = {}) {
  const numCtx = opts.num_ctx || 8192;
  const temp = opts.temperature || 0.3;
  return new Promise((resolve, reject) => {
    const url = new URL("/api/chat", ollamaUrl);
    const options = { hostname: url.hostname, port: url.port, path: url.pathname, method: "POST", headers: { "Content-Type": "application/json" } };
    let body = "";
    const req = http.request(options, (res) => {
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => {
        try {
          const parsed = JSON.parse(body);
          resolve(parsed.message ? parsed.message.content : body);
        } catch(e) {
          // Streaming format fallback
          let fullText = "";
          body.split("\n").filter(l => l.trim()).forEach(line => {
            try { const p = JSON.parse(line); if (p.message && p.message.content) fullText += p.message.content; } catch(e2) {}
          });
          resolve(fullText || body);
        }
      });
      res.on("error", reject);
    });
    req.on("error", reject);
    req.setTimeout(180000, () => { req.destroy(); reject(new Error("Ollama timeout")); });
    req.write(JSON.stringify({ model, messages, stream: false, keep_alive: "30m", options: { num_ctx: numCtx, temperature: temp } }));
    req.end();
  });
}

// =============================================
// Browser Agent Loop
// =============================================
async function runBrowserAgent(message, sessionKey, model, ollamaUrl, res) {
  const MAX_ITERATIONS = 15;

  // Step 1: Ensure browser is running
  emitActivity(res, "browser", "running", { action: "ブラウザ起動中...", detail: "Chrome起動中..." });
  const browserOk = await ensureBrowserRunning();
  if (!browserOk) {
    emitActivity(res, "browser", "done", { action: "ブラウザ起動失敗" });
    res.write("data: " + JSON.stringify({ content: "ブラウザの起動に失敗しました。`openclaw browser start` を手動で実行してみてください。", done: true, sessionKey }) + "\n\n");
    res.end();
    return;
  }
  emitActivity(res, "browser", "done", { action: "ブラウザ起動中...", detail: "起動完了" });

  // Build conversation for the agent
  let agentMessages = [
    { role: "system", content: BROWSER_AGENT_SYSTEM_PROMPT },
    { role: "user", content: message }
  ];
  let fullResponse = "";

  for (let iteration = 0; iteration < MAX_ITERATIONS; iteration++) {
    // Step 2: Take snapshot
    emitActivity(res, "browser", "running", { action: "snapshot", detail: "ページ解析中... (" + (iteration + 1) + "/" + MAX_ITERATIONS + ")" });
    let snapshot;
    try {
      snapshot = execBrowser("snapshot --format ai", 15000);
    } catch(e) {
      snapshot = "(snapshot failed: " + e.message + ")";
    }
    emitActivity(res, "browser", "done", { action: "snapshot", detail: "完了" });

    // Add snapshot to conversation (truncate to prevent context overflow)
    const snapshotText = typeof snapshot === "string" ? snapshot : JSON.stringify(snapshot, null, 2);
    agentMessages.push({ role: "user", content: "## Current Page Snapshot\n" + snapshotText.slice(0, 8000) });

    // Sliding window: keep system + original user message + last 4 snapshot/response pairs
    if (agentMessages.length > 10) {
      agentMessages = [agentMessages[0], agentMessages[1], ...agentMessages.slice(-8)];
    }

    // Step 3: Ask LLM for next action
    emitActivity(res, "browser", "running", { action: "thinking", detail: "次のアクションを判断中..." });
    let llmResponse;
    try {
      llmResponse = await callOllamaSync(ollamaUrl, model, agentMessages);
    } catch(e) {
      res.write("data: " + JSON.stringify({ content: "\n\nLLMエラー: " + e.message, done: true, sessionKey }) + "\n\n");
      res.end();
      return;
    }
    emitActivity(res, "browser", "done", { action: "thinking", detail: "完了" });

    // Add response to conversation
    agentMessages.push({ role: "assistant", content: llmResponse });

    // Stream explanation text (everything outside the action block)
    const explanationText = llmResponse.replace(/```action\s*\n[\s\S]*?```/g, "").replace(/<think>[\s\S]*?<\/think>/g, "").trim();
    if (explanationText) {
      fullResponse += explanationText + "\n\n";
      res.write("data: " + JSON.stringify({ content: explanationText + "\n\n", done: false }) + "\n\n");
    }

    // Step 4: Parse action
    const action = parseAction(llmResponse);
    if (!action) {
      fullResponse += "(アクション解析失敗 — 再試行)\n";
      agentMessages.push({ role: "user", content: "アクションJSONが見つかりませんでした。```action {...} ``` 形式で出力してください。" });
      continue;
    }

    // Step 5: Check for "done"
    if (action.action === "done") {
      if (action.summary) {
        fullResponse += action.summary;
        res.write("data: " + JSON.stringify({ content: action.summary, done: false }) + "\n\n");
      }
      break;
    }

    // Step 6: Execute the action
    emitActivity(res, "browser", "running", { action: action.action, detail: actionDescription(action) });
    try {
      executeAction(action);
      emitActivity(res, "browser", "done", { action: action.action, detail: "完了" });
    } catch(e) {
      emitActivity(res, "browser", "done", { action: action.action, detail: "エラー: " + e.message });
      agentMessages.push({ role: "user", content: "Action failed with error: " + e.message + "\nPlease try a different approach." });
    }

    // Brief pause between iterations
    await new Promise(r => setTimeout(r, 500));
  }

  // Save response to DB
  db.prepare("INSERT INTO chat_messages (sessionKey, role, content, model, timestamp) VALUES (?,?,?,?,?)")
    .run(sessionKey, "assistant", fullResponse, model + " (browser-agent)", new Date().toISOString());

  res.write("data: " + JSON.stringify({ content: "", done: true, sessionKey }) + "\n\n");
  res.end();
}

// =============================================
// Workspace & Git Status API
// =============================================
const AGENT_WORKSPACE = path.join(os.homedir(), "easyclaw-workspace");

app.get("/api/workspace/status", auth, (req, res) => {
  const ws = AGENT_WORKSPACE;
  if (!fs.existsSync(ws)) {
    fs.mkdirSync(ws, { recursive: true });
  }
  const result = { path: ws, exists: true, git: null, files: 0 };
  try {
    // Count files
    const files = execSync('dir /b /a:-d "' + ws + '" 2>nul', { shell: true, encoding: "utf8", timeout: 5000 }).trim().split("\n").filter(f => f.trim());
    result.files = files.length;
  } catch(e) { result.files = 0; }
  try {
    // Check if git repo
    execSync("git rev-parse --git-dir", { cwd: ws, shell: true, encoding: "utf8", timeout: 5000, stdio: ["pipe","pipe","pipe"] });
    const branch = execSync("git branch --show-current", { cwd: ws, shell: true, encoding: "utf8", timeout: 5000, stdio: ["pipe","pipe","pipe"] }).trim();
    let remote = "";
    try { remote = execSync("git remote get-url origin", { cwd: ws, shell: true, encoding: "utf8", timeout: 5000, stdio: ["pipe","pipe","pipe"] }).trim(); } catch(e) {}
    let status = "";
    try { status = execSync("git status --porcelain", { cwd: ws, shell: true, encoding: "utf8", timeout: 5000, stdio: ["pipe","pipe","pipe"] }).trim(); } catch(e) {}
    const changed = status ? status.split("\n").length : 0;
    let ahead = 0, behind = 0;
    try {
      const ab = execSync("git rev-list --left-right --count HEAD...@{u}", { cwd: ws, shell: true, encoding: "utf8", timeout: 5000, stdio: ["pipe","pipe","pipe"] }).trim().split(/\s+/);
      ahead = parseInt(ab[0]) || 0;
      behind = parseInt(ab[1]) || 0;
    } catch(e) {}
    result.git = { branch, remote, changed, ahead, behind };
  } catch(e) { /* not a git repo */ }
  res.json(result);
});

// =============================================
// Coding Agent — File ops, shell, search tools
// =============================================

const CODING_AGENT_SYSTEM_PROMPT = `You are a coding agent. You build projects by calling tools one at a time.

IMPORTANT: Every response MUST contain exactly one tool call in this format:

\`\`\`tool
{"tool": "TOOL_NAME", ...params}
\`\`\`
短い説明（日本語1文）

TOOLS:
1. file_write — ファイル作成/上書き: {"tool":"file_write","path":"app.py","content":"CODE_HERE"}
2. file_edit — ファイル部分編集 (search/replace): {"tool":"file_edit","path":"app.py","old_string":"old code","new_string":"new code"}
3. file_read — ファイル読取: {"tool":"file_read","path":"app.py"}
4. list_files — ディレクトリ一覧: {"tool":"list_files","path":"."}
5. grep — コード内検索 (regex対応): {"tool":"grep","pattern":"TODO|FIXME","path":".","include":"*.py"}
6. shell — コマンド実行: {"tool":"shell","command":"python app.py"}
7. done — 完了報告: {"tool":"done","summary":"## 完了\\n\\n作成ファイル:\\n- app.py\\n\\n実行方法: python app.py"}

WORKFLOW — Follow this order:
1. PLAN: Think about what files and structure you need before writing any code.
2. CREATE: Write all files using file_write. Write COMPLETE, working code in each file.
3. SETUP: Install dependencies (pip install, npm install) if needed.
4. VERIFY: Run the program to check it works.
5. FIX: If there's an error, read the error carefully, fix the root cause. Do NOT repeat the same fix.
6. DONE: Call done with a summary of what was created.

EXAMPLE 1 — Creating a file:
\`\`\`tool
{"tool":"file_write","path":"main.py","content":"import random\\n\\ndef roll():\\n    return random.randint(1,6)\\n\\nprint(f'You rolled: {roll()}')"}
\`\`\`
サイコロプログラムを作成しました。

EXAMPLE 2 — Editing part of a file:
\`\`\`tool
{"tool":"file_edit","path":"main.py","old_string":"return random.randint(1,6)","new_string":"return random.randint(1,20)"}
\`\`\`
ダイスの面数を20に変更しました。

EXAMPLE 3 — Running a command:
\`\`\`tool
{"tool":"shell","command":"python main.py"}
\`\`\`
プログラムを実行して動作確認します。

EXAMPLE 4 — Finishing:
\`\`\`tool
{"tool":"done","summary":"## 完了\\n\\nサイコロプログラムを作成しました。\\n\\n### 作成ファイル\\n- main.py — サイコロを振るプログラム\\n\\n### 実行方法\\n\`python main.py\`"}
\`\`\`

CRITICAL RULES:
- Output EXACTLY ONE \`\`\`tool block per response. No exceptions.
- Path is relative to workspace. Never use absolute paths.
- Use file_edit to modify existing files — find the exact old_string and replace with new_string.
- Use list_files and grep to understand existing code before editing.
- For multi-file projects: create each file in separate turns.
- After creating all files, run setup commands (npm install, pip install, etc.)
- Always finish with "done" tool. The summary should use Markdown formatting.
- Explanations: 1 sentence in Japanese AFTER the tool block.
- NEVER output code outside of file_write. No raw code blocks.
- NEVER use rm -rf or destructive commands.

ANTI-LOOP RULES — EXTREMELY IMPORTANT:
- If the same shell command fails TWICE with the same error, do NOT run it again. Fix the root cause or try a completely different approach.
- If file_edit fails, do NOT retry with the same old_string. Use file_read to see the actual file content first.
- NEVER edit the same file more than 3 times total. If it still doesn't work, rewrite the entire file with file_write.
- If you are stuck in a loop, call done immediately and explain what went wrong.
- When an error occurs, read the FULL error message and fix the actual root cause, not a guess.

ERROR FIXING RULES — CRITICAL:
- When a Python IndentationError or SyntaxError occurs: ALWAYS rewrite the ENTIRE file using file_write. Do NOT use file_edit for fixing indentation. JSON encoding can corrupt indentation.
- When any runtime error occurs after file_edit: use file_read first to see the actual file state, then rewrite with file_write.
- file_edit is ONLY for small, simple single-line replacements where indentation does not change. For anything involving indentation changes, use file_write to rewrite the whole file.

CODING BEST PRACTICES:
- Write simple, complete, working code. Include ALL necessary imports, functions, and error handling from the start.
- For GitHub data: use the GitHub REST API (https://api.github.com). Example: GET /search/repositories?q=stars:>1000&sort=stars
- For web APIs: use 'requests' library in Python or built-in 'fetch' in Node.js.
- NEVER use web scraping (BeautifulSoup, cheerio) when an official API exists.
- Include proper error handling in your code from the first version.
- Write the COMPLETE file content in file_write. Do not leave placeholders or TODOs.
- For Python: ensure consistent indentation (4 spaces). Test indentation visually before writing.
- For interactive programs: do NOT use input() for CLIs run from shell tool. Use command-line arguments or hardcoded test values instead.
- NEVER put actual newlines inside f-strings or string literals. Use separate print() calls or string concatenation instead.
- Keep your code simple and straightforward. A working simple solution is better than a broken complex one.`;

// Execute a coding agent tool
function executeCodingTool(action) {
  // Ensure workspace exists
  if (!fs.existsSync(AGENT_WORKSPACE)) {
    fs.mkdirSync(AGENT_WORKSPACE, { recursive: true });
  }

  switch (action.tool) {
    case "file_write": {
      const fullPath = path.resolve(AGENT_WORKSPACE, action.path);
      if (!fullPath.startsWith(AGENT_WORKSPACE)) throw new Error("Path outside workspace");
      const dir = path.dirname(fullPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

      let content = action.content;

      // Auto-fix: repair newlines inside Python string literals
      // This happens when LLM outputs \n in JSON which gets decoded to actual newlines
      if (action.path.endsWith(".py")) {
        const lines = content.split("\n");
        const fixed = [];
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          // Check if line has an unclosed string (odd number of unescaped quotes)
          const singleQ = (line.match(/(?:^|[^\\])'/g) || []).length;
          const doubleQ = (line.match(/(?:^|[^\\])"/g) || []).length;
          const fstringOpen = (line.match(/f'/g) || []).length;
          // If a line has unclosed single or double quotes, join with next line using \n
          if ((singleQ % 2 !== 0 || doubleQ % 2 !== 0) && i + 1 < lines.length) {
            // Check next line closes the string
            const nextLine = lines[i + 1];
            const nextSingleQ = (nextLine.match(/(?:^|[^\\])'/g) || []).length;
            const nextDoubleQ = (nextLine.match(/(?:^|[^\\])"/g) || []).length;
            if (singleQ % 2 !== 0 && nextSingleQ % 2 !== 0) {
              fixed.push(line + "\\n" + nextLine);
              i++; // skip next line
              continue;
            }
            if (doubleQ % 2 !== 0 && nextDoubleQ % 2 !== 0) {
              fixed.push(line + "\\n" + nextLine);
              i++; // skip next line
              continue;
            }
          }
          fixed.push(line);
        }
        content = fixed.join("\n");
      }

      fs.writeFileSync(fullPath, content, "utf8");
      return "File written: " + action.path + " (" + content.length + " bytes)";
    }
    case "file_edit": {
      const fullPath = path.resolve(AGENT_WORKSPACE, action.path);
      if (!fullPath.startsWith(AGENT_WORKSPACE)) throw new Error("Path outside workspace");
      if (!fs.existsSync(fullPath)) return "Error: File not found: " + action.path;
      const content = fs.readFileSync(fullPath, "utf8");
      const oldStr = action.old_string;
      const newStr = action.new_string;
      if (!oldStr) return "Error: old_string is required";
      const occurrences = content.split(oldStr).length - 1;
      if (occurrences === 0) return "Error: old_string not found in " + action.path + ". Use file_read to check current content.";
      if (occurrences > 1) return "Error: old_string found " + occurrences + " times in " + action.path + ". Provide more context to make it unique.";
      const newContent = content.replace(oldStr, newStr);
      fs.writeFileSync(fullPath, newContent, "utf8");
      return "File edited: " + action.path + " (replaced " + oldStr.length + " chars → " + newStr.length + " chars)";
    }
    case "file_read": {
      const fullPath = path.resolve(AGENT_WORKSPACE, action.path);
      if (!fullPath.startsWith(AGENT_WORKSPACE)) throw new Error("Path outside workspace");
      if (!fs.existsSync(fullPath)) return "Error: File not found: " + action.path;
      const content = fs.readFileSync(fullPath, "utf8");
      // Add line numbers for easier reference
      const lines = content.split("\n");
      const numbered = lines.map((l, i) => (i + 1) + "│" + l).join("\n");
      return numbered.length > 6000 ? numbered.slice(0, 6000) + "\n...(truncated at line ~" + Math.floor(6000 / 40) + ")" : numbered;
    }
    case "list_files": {
      const listPath = action.path || ".";
      const fullPath = path.resolve(AGENT_WORKSPACE, listPath);
      if (!fullPath.startsWith(AGENT_WORKSPACE)) throw new Error("Path outside workspace");
      if (!fs.existsSync(fullPath)) return "Error: Directory not found: " + listPath;
      function listDir(dir, prefix, depth) {
        if (depth > 4) return prefix + "...(max depth)\n";
        let result = "";
        try {
          const entries = fs.readdirSync(dir, { withFileTypes: true })
            .filter(e => !e.name.startsWith(".") && e.name !== "node_modules" && e.name !== "__pycache__" && e.name !== ".git");
          for (const entry of entries) {
            const entryPath = path.join(dir, entry.name);
            if (entry.isDirectory()) {
              result += prefix + "📁 " + entry.name + "/\n";
              result += listDir(entryPath, prefix + "  ", depth + 1);
            } else {
              const stat = fs.statSync(entryPath);
              const size = stat.size < 1024 ? stat.size + "B" : Math.round(stat.size / 1024) + "KB";
              result += prefix + "📄 " + entry.name + " (" + size + ")\n";
            }
          }
        } catch(e) {}
        return result;
      }
      const tree = listDir(fullPath, "", 0);
      return tree || "(empty directory)";
    }
    case "grep": {
      const pattern = action.pattern;
      if (!pattern) return "Error: pattern is required";
      const searchPath = path.resolve(AGENT_WORKSPACE, action.path || ".");
      if (!searchPath.startsWith(AGENT_WORKSPACE)) throw new Error("Path outside workspace");
      const include = action.include || "*";
      try {
        // Use findstr on Windows with regex support
        let cmd;
        if (include !== "*") {
          cmd = 'findstr /s /n /r /c:"' + pattern.replace(/"/g, '\\"') + '" "' + searchPath + '\\' + include + '" 2>nul';
        } else {
          cmd = 'findstr /s /n /r /c:"' + pattern.replace(/"/g, '\\"') + '" "' + searchPath + '\\*.*" 2>nul';
        }
        const result = execSync(cmd, { cwd: AGENT_WORKSPACE, timeout: 15000, shell: true, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
        // Format output: strip workspace prefix for cleaner display
        const cleaned = result.replace(new RegExp(AGENT_WORKSPACE.replace(/\\/g, "\\\\") + "\\\\?", "g"), "");
        return cleaned.length > 4000 ? cleaned.slice(0, 4000) + "\n...(truncated)" : (cleaned || "(no matches)");
      } catch(e) {
        return "(no matches)";
      }
    }
    case "search": {
      // Legacy search — redirect to grep or list_files based on pattern
      const pattern = action.pattern || "*";
      const searchIn = action.in || ".";
      const searchPath = path.resolve(AGENT_WORKSPACE, searchIn);
      if (!searchPath.startsWith(AGENT_WORKSPACE)) throw new Error("Path outside workspace");
      try {
        let cmd;
        if (pattern.includes("*") || pattern.includes("?")) {
          cmd = 'dir /s /b "' + searchPath + '\\' + pattern + '" 2>nul';
        } else {
          cmd = 'findstr /s /i /n "' + pattern.replace(/"/g, '\\"') + '" "' + searchPath + '\\*" 2>nul';
        }
        const result = execSync(cmd, { cwd: AGENT_WORKSPACE, timeout: 10000, shell: true, encoding: "utf8", stdio: ["pipe", "pipe", "pipe"] });
        return result.length > 3000 ? result.slice(0, 3000) + "\n...(truncated)" : (result || "(no matches)");
      } catch(e) {
        return "(no matches)";
      }
    }
    case "shell": {
      const cmd = action.command;
      // Block dangerous commands
      if (/rm\s+-rf\s+[\/~]|rmdir\s+\/s|format\s+c:|del\s+\/f\s+\/s/i.test(cmd)) {
        return "Error: Dangerous command blocked";
      }
      try {
        const result = execSync(cmd, {
          cwd: AGENT_WORKSPACE,
          timeout: 60000,
          shell: true,
          encoding: "utf8",
          stdio: ["pipe", "pipe", "pipe"]
        });
        return result.length > 4000 ? result.slice(0, 4000) + "\n...(truncated)" : (result || "(no output)");
      } catch(e) {
        const stderr = (e.stderr || "").trim();
        const stdout = (e.stdout || "").trim();
        return "Error (exit " + (e.status || "?") + "):\n" + (stderr || stdout || e.message).slice(0, 2000);
      }
    }
    default:
      throw new Error("Unknown tool: " + action.tool);
  }
}

// Repair JSON that contains actual newlines inside string values
function repairJSON(raw) {
  // Try as-is first
  try { return JSON.parse(raw); } catch(e) {}

  // Strategy 1: Replace actual newlines inside strings with \n
  // Find the "content" field value and escape newlines within it
  const contentMatch = raw.match(/"content"\s*:\s*"([\s\S]*)"(\s*\})\s*$/);
  if (contentMatch) {
    const before = raw.slice(0, raw.indexOf(contentMatch[1]));
    const content = contentMatch[1];
    const after = contentMatch[2];
    const escaped = content
      .replace(/\\/g, "\\\\")  // escape backslashes first
      .replace(/\n/g, "\\n")   // escape actual newlines
      .replace(/\r/g, "\\r")   // escape carriage returns
      .replace(/\t/g, "\\t");  // escape tabs
    try { return JSON.parse(before + escaped + after); } catch(e) {}
  }

  // Strategy 2: Brute force — escape ALL actual newlines between quotes
  const fixed = raw.replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t");
  try { return JSON.parse(fixed); } catch(e) {}

  // Strategy 3: Extract fields manually for file_write
  const toolMatch = raw.match(/"tool"\s*:\s*"(\w+)"/);
  const pathMatch = raw.match(/"path"\s*:\s*"([^"]+)"/);
  if (toolMatch && toolMatch[1] === "file_write" && pathMatch) {
    // Extract content between first "content":" and last "}
    const cIdx = raw.indexOf('"content"');
    if (cIdx !== -1) {
      const colonIdx = raw.indexOf(':', cIdx);
      const quoteIdx = raw.indexOf('"', colonIdx + 1);
      // Find the last "} pattern
      let endIdx = raw.lastIndexOf('"}');
      if (endIdx === -1) endIdx = raw.lastIndexOf('"');
      if (quoteIdx !== -1 && endIdx > quoteIdx) {
        const content = raw.slice(quoteIdx + 1, endIdx)
          .replace(/\\n/g, "\n").replace(/\\t/g, "\t").replace(/\\r/g, "\r")
          .replace(/\n/g, "\n"); // normalize
        return { tool: "file_write", path: pathMatch[1], content: content };
      }
    }
  }

  return null;
}

// Parse tool JSON from LLM response — robust multi-fallback
function parseCodingTool(text) {
  // 1. Standard ```tool ... ``` fenced block
  const fenced = text.match(/```tool\s*\n?([\s\S]*?)```/);
  if (fenced) {
    const result = repairJSON(fenced[1].trim());
    if (result) return result;
  }
  // 2. Any ```json or ``` block containing "tool":
  const anyFence = text.match(/```(?:json)?\s*\n?([\s\S]*?)```/);
  if (anyFence && anyFence[1].includes('"tool"')) {
    const result = repairJSON(anyFence[1].trim());
    if (result) return result;
  }
  // 3. Single-line JSON with "tool" key
  const singleLine = text.match(/\{[^{}]*"tool"\s*:\s*"[^"]+?"[^{}]*\}/);
  if (singleLine) {
    const result = repairJSON(singleLine[0]);
    if (result) return result;
  }
  // 4. Multi-line JSON (for file_write with long content)
  const multiLine = text.match(/\{[\s\S]*?"tool"\s*:\s*"[^"]+?"[\s\S]*?\n\s*\}/);
  if (multiLine) {
    const result = repairJSON(multiLine[0]);
    if (result) return result;
  }
  // 5. Heuristic: detect intent from natural language
  const doneMatch = text.match(/(?:完了|done|finished|タスク.*完了)/i);
  if (doneMatch && text.length < 500) {
    const cleanText = text.replace(/<think>[\s\S]*?<\/think>/g, "").trim();
    return { tool: "done", summary: cleanText };
  }
  return null;
}

// Tool description for activity display
function toolDescription(action) {
  switch (action.tool) {
    case "file_write": return action.path;
    case "file_edit": return action.path;
    case "file_read": return action.path;
    case "list_files": return action.path || ".";
    case "grep": return (action.pattern || "").slice(0, 40) + (action.include ? " (" + action.include + ")" : "");
    case "shell": return (action.command || "").slice(0, 60);
    case "search": return action.pattern + (action.in ? " in " + action.in : "");
    default: return action.tool;
  }
}

// Gather workspace context for agent's initial message
function getWorkspaceContext() {
  let context = "";
  // File listing (recursive, max 3 levels)
  function listDir(dir, prefix, depth) {
    if (depth > 3) return "";
    let result = "";
    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true })
        .filter(e => !e.name.startsWith(".") && e.name !== "node_modules" && e.name !== "__pycache__" && e.name !== ".git");
      for (const entry of entries) {
        const entryPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
          result += prefix + entry.name + "/\n";
          result += listDir(entryPath, prefix + "  ", depth + 1);
        } else {
          result += prefix + entry.name + "\n";
        }
      }
    } catch(e) {}
    return result;
  }
  const tree = listDir(AGENT_WORKSPACE, "  ", 0);
  if (tree) {
    context += "\nExisting files:\n" + tree;
  } else {
    context += "\nWorkspace is empty (new project).\n";
  }
  // Git status
  try {
    execSync("git rev-parse --git-dir", { cwd: AGENT_WORKSPACE, shell: true, encoding: "utf8", timeout: 3000, stdio: ["pipe", "pipe", "pipe"] });
    const branch = execSync("git branch --show-current", { cwd: AGENT_WORKSPACE, shell: true, encoding: "utf8", timeout: 3000, stdio: ["pipe", "pipe", "pipe"] }).trim();
    context += "Git: branch=" + branch;
    try {
      const status = execSync("git status --porcelain", { cwd: AGENT_WORKSPACE, shell: true, encoding: "utf8", timeout: 3000, stdio: ["pipe", "pipe", "pipe"] }).trim();
      if (status) {
        context += ", " + status.split("\n").length + " changed files";
      } else {
        context += ", clean";
      }
    } catch(e) {}
    context += "\n";
  } catch(e) {
    context += "Git: not initialized\n";
  }
  return context;
}

// Coding Agent Loop — with robust error recovery
async function runCodingAgent(message, sessionKey, model, ollamaUrl, res) {
  const MAX_ITERATIONS = 20;
  const MAX_PARSE_FAILURES = 3;

  // Ensure workspace
  if (!fs.existsSync(AGENT_WORKSPACE)) {
    fs.mkdirSync(AGENT_WORKSPACE, { recursive: true });
  }

  emitActivity(res, "agent", "running", { action: "planning", detail: "タスクを分析中..." });

  // Gather workspace context
  const wsContext = getWorkspaceContext();

  let agentMessages = [
    { role: "system", content: CODING_AGENT_SYSTEM_PROMPT },
    { role: "user", content: message + "\n\nWorkspace: " + AGENT_WORKSPACE + "\nOS: Windows\n" + wsContext }
  ];
  let fullResponse = "";
  let parseFailures = 0;
  let toolStep = 0;

  // Loop detection — track recent actions for repetition detection
  const recentActions = []; // [{tool, target, resultHash}]
  function getActionKey(tool) {
    if (tool.tool === "shell") return "shell:" + tool.command;
    if (tool.tool === "file_edit") return "edit:" + tool.path + ":" + (tool.old_string || "").slice(0, 50);
    return tool.tool + ":" + (tool.path || tool.pattern || "");
  }
  function detectLoop(tool) {
    const key = getActionKey(tool);
    const similar = recentActions.filter(a => a.key === key);
    return similar.length >= 2; // Same action attempted 2+ times already
  }
  // Track file edit counts per file
  const fileEditCounts = {};

  for (let iteration = 0; iteration < MAX_ITERATIONS; iteration++) {
    // Ask LLM for next tool call
    emitActivity(res, "agent", "running", { action: "thinking", detail: "ステップ " + (iteration + 1) + "/" + MAX_ITERATIONS });
    let llmResponse;
    try {
      llmResponse = await callOllamaSync(ollamaUrl, model, agentMessages);
    } catch(e) {
      res.write("data: " + JSON.stringify({ content: "\n\nLLMエラー: " + e.message, done: true, sessionKey }) + "\n\n");
      res.end();
      return;
    }
    emitActivity(res, "agent", "done", { action: "thinking" });

    agentMessages.push({ role: "assistant", content: llmResponse });

    // Parse tool call FIRST — before streaming anything
    const tool = parseCodingTool(llmResponse);

    if (!tool) {
      parseFailures++;
      console.log("[Agent] Parse failure " + parseFailures + "/" + MAX_PARSE_FAILURES + " — raw:", llmResponse.slice(0, 200));

      if (parseFailures >= MAX_PARSE_FAILURES) {
        // Abort — too many failures
        const abortMsg = "エージェントがツール形式を出力できませんでした。もう一度お試しください。";
        fullResponse += abortMsg;
        res.write("data: " + JSON.stringify({ content: abortMsg, done: false }) + "\n\n");
        break;
      }

      // Strong correction — do NOT stream the garbage text
      agentMessages.push({ role: "user", content: 'WRONG FORMAT. You MUST output:\n\n```tool\n{"tool":"file_write","path":"filename.py","content":"your code"}\n```\n\nOutput ONLY the ```tool block. Nothing else.' });
      continue;
    }

    // Tool parsed successfully — reset failure counter
    parseFailures = 0;
    toolStep++;

    // --- Loop Detection ---
    if (tool.tool !== "done" && detectLoop(tool)) {
      console.log("[Agent] Loop detected at step " + toolStep + " — forcing different approach");
      const loopMsg = "LOOP DETECTED: You have already tried this exact same action twice. You MUST either:\n1. Try a completely different approach\n2. Rewrite the entire file from scratch with file_write instead of file_edit\n3. If you cannot fix it, call done and explain what went wrong\n\nDo NOT repeat the same action.";
      agentMessages.push({ role: "user", content: loopMsg });
      continue;
    }

    // Track file edit count
    if (tool.tool === "file_edit" && tool.path) {
      fileEditCounts[tool.path] = (fileEditCounts[tool.path] || 0) + 1;
      if (fileEditCounts[tool.path] > 3) {
        console.log("[Agent] Too many edits to " + tool.path + " — forcing rewrite");
        agentMessages.push({ role: "user", content: "You have edited " + tool.path + " too many times (" + fileEditCounts[tool.path] + "). The file is likely broken. Use file_read to see the current state, then REWRITE the entire file with file_write." });
        continue;
      }
    }

    // Record action for loop detection
    recentActions.push({ key: getActionKey(tool), step: toolStep });

    // Extract and stream explanation text (only on successful parse)
    const explanationText = llmResponse
      .replace(/```(?:tool|json)?\s*\n?[\s\S]*?```/g, "")
      .replace(/<think>[\s\S]*?<\/think>/g, "")
      .replace(/^\s*\n/gm, "")
      .trim();

    if (explanationText && explanationText.length > 3 && explanationText.length < 500) {
      fullResponse += explanationText + "\n\n";
      res.write("data: " + JSON.stringify({ content: explanationText + "\n\n", done: false }) + "\n\n");
    }

    // Check for done
    if (tool.tool === "done") {
      if (tool.summary) {
        fullResponse += tool.summary;
        res.write("data: " + JSON.stringify({ content: tool.summary, done: false }) + "\n\n");
      }
      break;
    }

    // Execute tool
    const toolLabel = tool.tool;
    emitActivity(res, "agent", "running", { action: toolLabel, detail: toolDescription(tool) });

    let result;
    try {
      result = executeCodingTool(tool);
      emitActivity(res, "agent", "done", { action: toolLabel, detail: "完了" });
    } catch(e) {
      result = "Error: " + e.message;
      emitActivity(res, "agent", "done", { action: toolLabel, detail: "エラー: " + e.message });
    }

    // Enhanced feedback — include iteration count and guidance on errors
    let feedback = "Tool result:\n" + result;
    if (result.startsWith("Error:") || result.includes("Error") || result.includes("Traceback")) {
      // Detect specific error types and give targeted guidance
      if (result.includes("IndentationError") || result.includes("SyntaxError")) {
        feedback += "\n\nCRITICAL: IndentationError/SyntaxError detected. You MUST rewrite the ENTIRE file using file_write (not file_edit). file_edit corrupts indentation.";
      } else if (result.includes("ModuleNotFoundError") || result.includes("No module named")) {
        feedback += "\n\nMissing module. Install it with: shell → pip install <module_name>";
      } else {
        feedback += "\n\nThe tool returned an error. Read the error carefully and fix the root cause. Do NOT retry the same approach.";
      }
    }
    feedback += "\n\nStep " + (iteration + 1) + "/" + MAX_ITERATIONS + ". Continue with the next tool call.";
    agentMessages.push({ role: "user", content: feedback });

    // Sliding window: keep system + original user + last N tool/response pairs
    if (agentMessages.length > 16) {
      agentMessages = [agentMessages[0], agentMessages[1], ...agentMessages.slice(-14)];
    }

    await new Promise(r => setTimeout(r, 200));
  }

  // If no meaningful response was generated, add a fallback
  if (!fullResponse.trim()) {
    fullResponse = "タスクを処理しましたが、結果を生成できませんでした。";
    res.write("data: " + JSON.stringify({ content: fullResponse, done: false }) + "\n\n");
  }

  // Save to DB
  db.prepare("INSERT INTO chat_messages (sessionKey, role, content, model, timestamp) VALUES (?,?,?,?,?)")
    .run(sessionKey, "assistant", fullResponse, model + " (coding-agent)", new Date().toISOString());

  res.write("data: " + JSON.stringify({ content: "", done: true, sessionKey }) + "\n\n");
  res.end();
}

// --- Chat Sessions & History ---
app.get("/api/local/chat/sessions", auth, (req, res) => {
  const sessions = db.prepare("SELECT * FROM chat_sessions WHERE email=? ORDER BY updatedAt DESC").all(req.user.email);
  res.json({ success: true, sessions });
});

app.get("/api/local/chat/history", auth, (req, res) => {
  const sessionKey = req.query.sessionKey;
  if (!sessionKey) return res.status(400).json({ error: "sessionKeyが必要です" });
  const messages = db.prepare("SELECT * FROM chat_messages WHERE sessionKey=? ORDER BY id").all(sessionKey);
  res.json({ success: true, messages });
});

app.delete("/api/local/chat/sessions/:key", auth, (req, res) => {
  const sessionKey = req.params.key;
  db.prepare("DELETE FROM chat_messages WHERE sessionKey=?").run(sessionKey);
  db.prepare("DELETE FROM chat_sessions WHERE sessionKey=? AND email=?").run(sessionKey, req.user.email);
  res.json({ success: true });
});

// --- Pre-warm Ollama model (load into memory on startup) ---
function prewarmOllama() {
  // Get a common model from settings or default
  const row = db.prepare("SELECT ollamaUrl, model FROM user_settings WHERE setupCompleted=1 LIMIT 1").get();
  const ollamaUrl = (row && row.ollamaUrl) || "http://localhost:11434";
  const model = (row && row.model) || "deepseek-r1:14b";

  console.log("[Prewarm] Loading model '" + model + "' into memory...");
  const url = new URL("/api/chat", ollamaUrl);
  const options = { hostname: url.hostname, port: url.port, path: url.pathname, method: "POST", headers: { "Content-Type": "application/json" } };

  const req = http.request(options, (res) => {
    let body = "";
    res.on("data", (chunk) => { body += chunk; });
    res.on("end", () => {
      console.log("[Prewarm] Model '" + model + "' is now loaded and ready");
    });
  });
  req.on("error", (e) => {
    console.log("[Prewarm] Ollama not reachable — model will load on first chat:", e.message);
  });
  req.setTimeout(30000, () => { req.destroy(); });
  // Send minimal request with keep_alive to load model without generating a long response
  req.write(JSON.stringify({ model, messages: [{ role: "user", content: "hi" }], stream: false, keep_alive: "30m", options: { num_predict: 1 } }));
  req.end();
}

// --- Cleanup on exit ---
process.on("SIGTERM", () => {
  if (gatewayProcess) gatewayProcess.kill("SIGTERM");
  process.exit(0);
});
process.on("SIGINT", () => {
  if (gatewayProcess) gatewayProcess.kill("SIGTERM");
  process.exit(0);
});

// --- Start Server ---
app.listen(3000, "0.0.0.0", () => {
  console.log("EasyClaw API running on port 3000");
  console.log("OpenClaw Gateway port:", OPENCLAW_GATEWAY_PORT);
  // Auto-start Gateway on boot
  autoStartGateway();
  // Pre-warm Ollama model so first chat is fast
  setTimeout(prewarmOllama, 1000);
});
