const express = require("express");
const { execSync } = require("child_process");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const app = express();
app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), handleStripeWebhook);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("/home/ubuntu/easyclaw-api/public"));
app.get("/", (req, res) => { res.sendFile("/home/ubuntu/easyclaw-api/public/lp.html"); });
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-here";

// JWT認証ミドルウェア
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ success: false, error: '認証が必要です' });
  }
  
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, error: 'トークンが無効です' });
    }
    req.user = user;
    next();
  });
}
const UD = "/opt/easyclaw/users";
const OC = "/home/ubuntu/.npm-global/bin/openclaw";
const BASE_URL = process.env.BASE_URL || "https://easyclaw.jp";
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const STRIPE_PRICES = { standard: process.env.STRIPE_PRICE_STANDARD || "" };
let stripe = null;
function getStripe() { if (!stripe && STRIPE_SECRET_KEY) stripe = require("stripe")(STRIPE_SECRET_KEY); return stripe; }
const PLAN_LIMITS = { free: { maxBots: 0, label: "Free" }, standard: { maxBots: 3, label: "スタンダード（￥980/週）" } };
const db = new Database("/home/ubuntu/easyclaw-api/users.db");
db.exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, email TEXT UNIQUE, password TEXT, createdAt TEXT)");
db.exec("CREATE TABLE IF NOT EXISTS otp_codes (id INTEGER PRIMARY KEY, email TEXT, code TEXT, expiresAt TEXT, used INTEGER DEFAULT 0)");
try { db.exec("ALTER TABLE users ADD COLUMN emailVerified INTEGER DEFAULT 0"); } catch(e) {}
const transporter = nodemailer.createTransport({ service: "gmail", auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_PASS } });
async function sendOTP(email) {
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  db.prepare("DELETE FROM otp_codes WHERE email=?").run(email);
  db.prepare("INSERT INTO otp_codes (email, code, expiresAt) VALUES (?,?,?)").run(email, code, expiresAt);
  await transporter.sendMail({
    from: '"EasyClaw" <' + process.env.GMAIL_USER + '>',
    to: email,
    subject: "【EasyClaw】認証コード: " + code,
    html: "<div style='font-family:sans-serif;max-width:400px;margin:0 auto;padding:32px;background:#1a1a2e;color:#fff;border-radius:12px'><h2 style='text-align:center;color:#ff5722'>EasyClaw</h2><p style='text-align:center'>あなたの認証コード:</p><div style='text-align:center;font-size:36px;font-weight:bold;letter-spacing:8px;padding:16px;background:#16213e;border-radius:8px;margin:16px 0'>" + code + "</div><p style='text-align:center;color:#999;font-size:12px'>このコードは10分間有効です</p></div>"
  });
  return code;
}
db.exec("CREATE TABLE IF NOT EXISTS deployments (id INTEGER PRIMARY KEY, userId TEXT, email TEXT, port INTEGER, model TEXT, status TEXT, createdAt TEXT)");
const addCol = (t, c, type, def) => { try { db.exec("ALTER TABLE " + t + " ADD COLUMN " + c + " " + type + " DEFAULT " + def); } catch(e) {} };
addCol("users", "plan", "TEXT", "free");
addCol("users", "stripeCustomerId", "TEXT", "NULL");
addCol("users", "stripeSubscriptionId", "TEXT", "NULL");
function auth(req, res, next) { const t = req.headers.authorization; if (!t) return res.status(401).json({ error: "\u30ed\u30b0\u30a4\u30f3\u5fc5\u9808" }); try { req.user = jwt.verify(t.replace("Bearer ", ""), JWT_SECRET); next(); } catch(e) { res.status(401).json({ error: "\u518d\u30ed\u30b0\u30a4\u30f3\u3057\u3066\u304f\u3060\u3055\u3044" }); } }
app.post("/api/register", async (req, res) => { try { const { email, password } = req.body; if (!email || !password) return res.status(400).json({ error: "メールとパスワードを入力" }); if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: "正しいメールアドレスを入力してください" }); if (password.length < 6) return res.status(400).json({ error: "パスワードは6文字以上" }); const existing = db.prepare("SELECT * FROM users WHERE email=?").get(email); if (existing && existing.emailVerified) return res.status(400).json({ error: "登録済みメール" }); if (existing && !existing.emailVerified) { db.prepare("UPDATE users SET password=? WHERE email=?").run(bcrypt.hashSync(password, 10), email); } else { const hash = bcrypt.hashSync(password, 10); db.prepare("INSERT INTO users (email, password, emailVerified, createdAt) VALUES (?,?,0,?)").run(email, hash, new Date().toISOString()); } await sendOTP(email); res.json({ success: true, needVerify: true, email }); } catch(e) { console.error("Register error:", e.message); res.status(500).json({ error: "登録に失敗しました" }); } });
app.post("/api/verify-otp", (req, res) => { try { const { email, code } = req.body; if (!email || !code) return res.status(400).json({ error: "コードを入力してください" }); const otp = db.prepare("SELECT * FROM otp_codes WHERE email=? AND code=? AND used=0").get(email, code); if (!otp) return res.status(400).json({ error: "認証コードが無効です" }); if (new Date(otp.expiresAt) < new Date()) return res.status(400).json({ error: "認証コードの有効期限が切れました" }); db.prepare("UPDATE otp_codes SET used=1 WHERE id=?").run(otp.id); db.prepare("UPDATE users SET emailVerified=1 WHERE email=?").run(email); const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" }); res.json({ success: true, token, email }); } catch(e) { res.status(500).json({ error: e.message }); } });
app.post("/api/resend-otp", async (req, res) => { try { const { email } = req.body; if (!email) return res.status(400).json({ error: "メールアドレスが必要です" }); await sendOTP(email); res.json({ success: true }); } catch(e) { res.status(500).json({ error: "送信失敗" }); } });
app.post("/api/login", async (req, res) => { const { email, password } = req.body; if (!email || !password) return res.status(400).json({ error: "メールとパスワードを入力" }); const user = db.prepare("SELECT * FROM users WHERE email=?").get(email); if (!user || !bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: "メールまたはパスワードが違います" }); if (!user.emailVerified) { await sendOTP(email); return res.json({ success: true, needVerify: true, email }); } const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" }); res.json({ success: true, token, email }); });
app.get("/api/subscription", auth, (req, res) => { const user = db.prepare("SELECT plan, stripeCustomerId, stripeSubscriptionId FROM users WHERE email=?").get(req.user.email); if (!user) return res.status(404).json({ error: "\u30e6\u30fc\u30b6\u30fc\u304c\u898b\u3064\u304b\u308a\u307e\u305b\u3093" }); const cnt = db.prepare("SELECT COUNT(*) as cnt FROM deployments WHERE email=?").get(req.user.email).cnt; const limits = PLAN_LIMITS[user.plan] || PLAN_LIMITS.free; res.json({ plan: user.plan || "free", planLabel: limits.label, maxBots: limits.maxBots, currentBots: cnt, canDeploy: cnt < limits.maxBots, hasSubscription: !!user.stripeSubscriptionId }); });
app.post("/api/stripe/checkout", auth, async (req, res) => { try { const s = getStripe(); if (!s) return res.status(500).json({ error: "Stripe\u672a\u8a2d\u5b9a\u3067\u3059" }); const { plan } = req.body; const priceId = STRIPE_PRICES[plan]; if (!priceId) return res.status(400).json({ error: "\u7121\u52b9\u306a\u30d7\u30e9\u30f3\u3067\u3059" }); const user = db.prepare("SELECT * FROM users WHERE email=?").get(req.user.email); let customerId = user.stripeCustomerId; if (!customerId) { const customer = await s.customers.create({ email: req.user.email }); customerId = customer.id; db.prepare("UPDATE users SET stripeCustomerId=? WHERE email=?").run(customerId, req.user.email); } if (user.stripeSubscriptionId) { return res.status(400).json({ error: "\u65e2\u306b\u30b5\u30d6\u30b9\u30af\u304c\u3042\u308a\u307e\u3059", redirect: "portal" }); } const session = await s.checkout.sessions.create({ customer: customerId, mode: "subscription", payment_method_types: ["card"], subscription_data: { trial_period_days: 3 }, line_items: [{ price: priceId, quantity: 1 }], success_url: BASE_URL + "/app.html?payment=success", cancel_url: BASE_URL + "/app.html?payment=cancelled", metadata: { email: req.user.email, plan } }); res.json({ url: session.url }); } catch(e) { console.error("Stripe checkout error:", e.message); res.status(500).json({ error: "\u6c7a\u6e08\u30da\u30fc\u30b8\u306e\u4f5c\u6210\u306b\u5931\u6557" }); } });
app.post("/api/stripe/portal", auth, async (req, res) => { try { const s = getStripe(); if (!s) return res.status(500).json({ error: "Stripe\u672a\u8a2d\u5b9a" }); const user = db.prepare("SELECT stripeCustomerId FROM users WHERE email=?").get(req.user.email); if (!user || !user.stripeCustomerId) return res.status(400).json({ error: "\u30b5\u30d6\u30b9\u30af\u304c\u3042\u308a\u307e\u305b\u3093" }); const session = await s.billingPortal.sessions.create({ customer: user.stripeCustomerId, return_url: BASE_URL + "/app.html" }); res.json({ url: session.url }); } catch(e) { res.status(500).json({ error: "\u30dd\u30fc\u30bf\u30eb\u4f5c\u6210\u5931\u6557" }); } });
async function handleStripeWebhook(req, res) { const s = getStripe(); if (!s) return res.status(400).send("Stripe not configured"); let event; try { if (STRIPE_WEBHOOK_SECRET) { event = s.webhooks.constructEvent(req.body, req.headers["stripe-signature"], STRIPE_WEBHOOK_SECRET); } else { event = JSON.parse(req.body); } } catch(e) { console.error("Webhook sig error:", e.message); return res.status(400).send("Webhook Error"); } console.log("[Stripe]", event.type); try { switch (event.type) { case "checkout.session.completed": { const session = event.data.object; const email = session.metadata && session.metadata.email || session.customer_email; const plan = session.metadata && session.metadata.plan; if (email && plan) { db.prepare("UPDATE users SET plan=?, stripeCustomerId=?, stripeSubscriptionId=? WHERE email=?").run(plan, session.customer, session.subscription, email); console.log("[Activated] " + email + " -> " + plan); } break; } case "customer.subscription.updated": { const sub = event.data.object; const user = db.prepare("SELECT * FROM users WHERE stripeCustomerId=?").get(sub.customer); if (!user) break; const priceId = sub.items.data[0] && sub.items.data[0].price && sub.items.data[0].price.id; let newPlan = "free"; if (priceId === STRIPE_PRICES.standard) newPlan = "standard"; if (!sub.cancel_at_period_end) { db.prepare("UPDATE users SET plan=?, stripeSubscriptionId=? WHERE email=?").run(newPlan, sub.id, user.email); console.log("[Updated] " + user.email + " -> " + newPlan); } break; } case "customer.subscription.deleted": { const sub2 = event.data.object; const user2 = db.prepare("SELECT * FROM users WHERE stripeCustomerId=?").get(sub2.customer); if (user2) { db.prepare("UPDATE users SET plan=?, stripeSubscriptionId=NULL WHERE email=?").run("free", user2.email); const deps = db.prepare("SELECT * FROM deployments WHERE email=?").all(user2.email); for (const d of deps) { try { execSync("docker stop claw-" + d.email.replace(/[^a-zA-Z0-9]/g, "-") + "-" + d.userId + " 2>/dev/null"); db.prepare("UPDATE deployments SET status=? WHERE userId=?").run("stopped", d.userId); } catch(e) {} } console.log("[Cancelled] " + user2.email + " -> free"); } break; } case "invoice.payment_failed": { const inv = event.data.object; const user3 = db.prepare("SELECT * FROM users WHERE stripeCustomerId=?").get(inv.customer); if (user3) console.log("[Payment failed] " + user3.email); break; } } } catch(e) { console.error("Webhook error:", e.message); } res.json({ received: true }); }
app.post("/api/deploy", auth, (req, res) => {
  try {
    const user = db.prepare("SELECT plan FROM users WHERE email=?").get(req.user.email);
    const plan = user && user.plan || "free";
    const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free;
    const cnt = db.prepare("SELECT COUNT(*) as cnt FROM deployments WHERE email=?").get(req.user.email).cnt;
    if (cnt >= limits.maxBots) {
      if (limits.maxBots === 0) return res.status(403).json({ error: "デプロイにはプランが必要です", code: "NO_PLAN" });
      return res.status(403).json({ error: limits.label + "の上限です", code: "LIMIT_REACHED" });
    }
    const { userId, apiProvider, apiKey, model, discordToken, discordUserId } = req.body;
    if (!userId || !apiKey) return res.status(400).json({ error: "Bot名とAPIキーは必須です" });
    if (!/^[a-zA-Z0-9_-]+$/.test(userId)) return res.status(400).json({ error: "Bot名は半角英数字・ハイフン・アンダースコアのみ使用可能です" });
    const containerName = "claw-" + req.user.email.replace(/[^a-zA-Z0-9]/g, "-") + "-" + userId;
    // 同名コンテナが既にあれば停止・削除
    try { execSync("docker rm -f " + containerName + " 2>/dev/null"); } catch(e) {}
    // コンテナ用設定ディレクトリを作成
    const userDir = path.join(UD, containerName);
    const od = path.join(userDir, ".openclaw");
    const ad = path.join(od, "agents/main/agent");
    const cd = path.join(od, "credentials");
    const wd = path.join(od, "workspace");
    execSync("sudo rm -rf " + userDir);
    fs.mkdirSync(ad, { recursive: true });
    fs.mkdirSync(cd, { recursive: true });
    fs.mkdirSync(wd, { recursive: true });
    const gt = crypto.randomBytes(24).toString("hex");
    // 設定ファイル作成
    fs.writeFileSync(path.join(ad, "auth.json"), JSON.stringify({ [apiProvider]: { type: "api_key", key: apiKey } }));
    fs.writeFileSync(path.join(ad, "auth-profiles.json"), JSON.stringify({ version: 1, profiles: { [apiProvider + ":default"]: { type: "api_key", provider: apiProvider, key: apiKey } }, lastGood: { [apiProvider]: apiProvider + ":default" } }));
    fs.writeFileSync(path.join(od, "openclaw.json"), JSON.stringify({
      auth: { profiles: { [apiProvider + ":default"]: { provider: apiProvider, mode: "api_key" } } },
      agents: { defaults: { model: { primary: model }, workspace: "/home/clawuser/.openclaw/workspace", compaction: { mode: "safeguard" }, maxConcurrent: 4 } },
      channels: { discord: { enabled: !!discordToken, token: discordToken || "", groupPolicy: "allowlist", guilds: {} } },
      gateway: { port: 20000, mode: "local", bind: "loopback", auth: { mode: "token", token: gt } },
      plugins: { entries: { discord: { enabled: true } } }
    }));
    if (discordUserId) { fs.writeFileSync(path.join(cd, "discord-allowFrom.json"), JSON.stringify({ version: 1, allowFrom: [discordUserId] })); }
    // 権限設定（セキュリティ強化）
    execSync("sudo chown -R 1001:1001 " + userDir);
    execSync("sudo chmod 700 " + od);
    execSync("sudo chmod 600 " + path.join(od, "openclaw.json"));
    execSync("sudo chmod 700 " + cd);
    // Dockerコンテナで起動（完全隔離）
    const dockerCmd = [
      "docker run -d",
      "--name " + containerName,
      
      
      "--restart=unless-stopped",
      "-v " + od + ":/home/clawuser/.openclaw:rw",
      "-e OPENCLAW_CONFIG_PATH=/home/clawuser/.openclaw/openclaw.json",
      "-e NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt",
      "-e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
      "-e NODE_OPTIONS=--use-openssl-ca",
      "easyclaw-base",
      "gateway", "run", "--allow-unconfigured"
    ].join(" ");
    execSync(dockerCmd);
    db.prepare("INSERT INTO deployments (userId,email,port,model,status,createdAt) VALUES (?,?,?,?,?,?)").run(userId, req.user.email, 0, model, "active", new Date().toISOString());
    res.json({ success: true, message: "デプロイ完了", userId: userId, port: 0, model: model });
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.get("/api/my-deployments", auth, (req, res) => { const deps = db.prepare("SELECT * FROM deployments WHERE email=?").all(req.user.email); if (!deps.length) return res.json({ exists: false, deployments: [] }); const result = deps.map(function(d) { let running = false; try { running = execSync("docker inspect -f {{.State.Running}} claw-" + req.user.email.replace(/[^a-zA-Z0-9]/g, "-") + "-" + d.userId + " 2>/dev/null").toString().trim() === "true"; } catch(e) {} return Object.assign({}, d, { running: running }); }); res.json({ exists: true, deployments: result }); });
app.get("/api/my-deployment", auth, (req, res) => { const dep = db.prepare("SELECT * FROM deployments WHERE email=?").get(req.user.email); if (!dep) return res.json({ exists: false }); try { const s = execSync("docker inspect -f {{.State.Running}} claw-" + req.user.email.replace(/[^a-zA-Z0-9]/g, "-") + "-" + dep.userId + " 2>/dev/null").toString().trim(); res.json({ exists: true, userId: dep.userId, email: dep.email, port: dep.port, model: dep.model, status: dep.status, createdAt: dep.createdAt, running: s === "true" }); } catch(e) { res.json({ exists: true, userId: dep.userId, email: dep.email, port: dep.port, model: dep.model, status: dep.status, createdAt: dep.createdAt, running: false }); } });
app.post("/api/stop/:userId", auth, (req, res) => { try { const dep = db.prepare("SELECT * FROM deployments WHERE userId=? AND email=?").get(req.params.userId, req.user.email); if (!dep) return res.status(403).json({ error: "no" }); const cn = "claw-" + req.user.email.replace(/[^a-zA-Z0-9]/g, "-") + "-" + req.params.userId; execSync("docker stop " + cn); db.prepare("UPDATE deployments SET status=? WHERE userId=?").run("stopped", req.params.userId); res.json({ message: "stopped" }); } catch(e) { res.status(500).json({ error: "fail" }); } });
app.post("/api/start/:userId", auth, (req, res) => { try { const dep = db.prepare("SELECT * FROM deployments WHERE userId=? AND email=?").get(req.params.userId, req.user.email); if (!dep) return res.status(403).json({ error: "no" }); const cn = "claw-" + req.user.email.replace(/[^a-zA-Z0-9]/g, "-") + "-" + req.params.userId; execSync("docker start " + cn); db.prepare("UPDATE deployments SET status=? WHERE userId=?").run("running", req.params.userId); res.json({ message: "started" }); } catch(e) { res.status(500).json({ error: "fail" }); } });
app.post("/api/delete/:userId", auth, (req, res) => { const u = req.params.userId; try { const cn = "claw-" + req.user.email.replace(/[^a-zA-Z0-9]/g, "-") + "-" + u; try { execSync("docker rm -f " + cn); } catch(e) {} execSync("rm -rf " + path.join(UD, cn)); db.prepare("DELETE FROM deployments WHERE userId=?").run(u); res.json({ message: "deleted" }); } catch(e) { res.status(500).json({ error: "fail" }); } });
app.get("/api/bot-info/:botId", auth, (req, res) => {
  try {
    var botId = req.params.botId;
    var dep = db.prepare("SELECT * FROM deployments WHERE userId = ? AND email = ?").get(botId, req.user.email);
    if (!dep) return res.status(403).json({ error: "権限がありません" });
    var cn = "claw-" + req.user.email.replace(/[^a-zA-Z0-9]/g, "-") + "-" + botId;
    var ocDir = path.join("/opt/easyclaw/users", cn, ".openclaw");
    var ocPath = path.join(ocDir, "openclaw.json");
    var authPath = path.join(ocDir, "agents/main/agent/auth.json");
    var credPath = path.join(ocDir, "credentials/discord-allowFrom.json");
    var info = { botId: botId, model: dep.model, provider: "", apiKeyMask: "", discordTokenMask: "", discordUserId: "" };
    try {
      var authJson = JSON.parse(execSync("sudo cat " + authPath).toString());
      var provider = Object.keys(authJson)[0];
      info.provider = provider;
      var key = authJson[provider].key || "";
      info.apiKeyMask = key.length > 8 ? key.slice(0,4) + "****" + key.slice(-4) : "****";
    } catch(e2) {}
    try {
      var ocJson = JSON.parse(execSync("sudo cat " + ocPath).toString());
      var dt = (ocJson.channels && ocJson.channels.discord && ocJson.channels.discord.token) || "";
      info.discordTokenMask = dt.length > 8 ? dt.slice(0,4) + "****" + dt.slice(-4) : "****";
    } catch(e3) {}
    try {
      var credJson = JSON.parse(execSync("sudo cat " + credPath).toString());
      info.discordUserId = (credJson.allowFrom && credJson.allowFrom[0]) || "";
    } catch(e4) {}
    res.json(info);
  } catch(e) { res.status(500).json({ error: e.message }); }
});
app.post("/api/update-bot/:botId", auth, async (req, res) => { try { var botId = req.params.botId; var dep = db.prepare("SELECT * FROM deployments WHERE userId = ? AND email = ?").get(botId, req.user.email); if (!dep) return res.status(403).json({ error: "このBotを変更する権限がありません" }); var cn = "claw-" + req.user.email.replace(/[^a-zA-Z0-9]/g, "-") + "-" + botId; var ocDir = path.join("/opt/easyclaw/users", cn, ".openclaw"); var ocPath = path.join(ocDir, "openclaw.json"); var authPath = path.join(ocDir, "agents/main/agent/auth.json"); var authProfPath = path.join(ocDir, "agents/main/agent/auth-profiles.json"); var credPath = path.join(ocDir, "credentials/discord-allowFrom.json"); try { execSync("sudo test -f " + ocPath); } catch(te) { return res.status(404).json({ error: "Bot設定ファイルが見つかりません" }); } if (req.body.apiProvider && req.body.apiKey) {
      var newProvider = req.body.apiProvider;
      var newKey = req.body.apiKey;
      var newAuth = {}; newAuth[newProvider] = { type: "api_key", key: newKey };
      execSync("sudo tee " + authPath, {input: JSON.stringify(newAuth)});
      var newProf = { version: 1, profiles: {}, lastGood: {} };
      var profId = newProvider + ":default";
      newProf.profiles[profId] = { type: "api_key", provider: newProvider, key: newKey };
      newProf.lastGood[newProvider] = profId;
      execSync("sudo tee " + authProfPath, {input: JSON.stringify(newProf)});
      var ocJson2 = JSON.parse(execSync("sudo cat " + ocPath).toString());
      ocJson2.auth = { profiles: {} }; ocJson2.auth.profiles[profId] = { provider: newProvider, mode: "api_key" };
      if (req.body.model) { ocJson2.agents.defaults.model.primary = req.body.model; }
      execSync("sudo tee " + ocPath, {input: JSON.stringify(ocJson2)});
    } else if (req.body.apiKey) {
      var authJson = JSON.parse(execSync("sudo cat " + authPath).toString()); var provider = Object.keys(authJson)[0]; authJson[provider].key = req.body.apiKey; execSync("sudo tee " + authPath, {input: JSON.stringify(authJson)}); var profJson = JSON.parse(execSync("sudo cat " + authProfPath).toString()); var profKey = Object.keys(profJson.profiles)[0]; profJson.profiles[profKey].key = req.body.apiKey; execSync("sudo tee " + authProfPath, {input: JSON.stringify(profJson)});
    } else if (req.body.model) {
      var ocJson3 = JSON.parse(execSync("sudo cat " + ocPath).toString());
      ocJson3.agents.defaults.model.primary = req.body.model;
      execSync("sudo tee " + ocPath, {input: JSON.stringify(ocJson3)});
    } if (req.body.discordToken) { var ocJson = JSON.parse(fs.readFileSync(ocPath, "utf8")); ocJson.channels.discord.token = req.body.discordToken; fs.writeFileSync(ocPath, JSON.stringify(ocJson)); } if (req.body.discordUserId) { var credJson = JSON.parse(fs.readFileSync(credPath, "utf8")); credJson.allowFrom = [req.body.discordUserId]; fs.writeFileSync(credPath, JSON.stringify(credJson)); } try { require("child_process").execSync("docker restart " + cn, { timeout: 15000 }); } catch(e) {} res.json({ success: true, message: "設定を更新しBotを再起動しました" }); } catch(e) { console.error("Update bot error:", e.message); res.status(500).json({ error: "設定の更新に失敗: " + e.message }); } });


// Gateway Proxy API
const WebSocket = require("ws");
function gatewayRPC(containerName, method, params, timeoutMs) {
  return new Promise((resolve, reject) => {
    var token;
    try { var ocJson = JSON.parse(execSync("sudo cat " + path.join("/opt/easyclaw/users", containerName, ".openclaw/openclaw.json")).toString()); token = ocJson.gateway.auth.token; } catch(e) { return reject(new Error("Cannot read gateway config")); }
    var paramsStr = JSON.stringify(params || {}).replace(/'/g, "'\''");
    var cmd = "docker exec " + containerName + " openclaw gateway call " + method + " --url ws://127.0.0.1:20000 --token " + token + " --params '" + paramsStr + "' --timeout " + (timeoutMs || 15000) + " --json 2>/dev/null";
    try {
      var out = execSync(cmd, { timeout: (timeoutMs || 15000) + 5000 }).toString().trim();
      var result = JSON.parse(out);
      resolve(result);
    } catch(e) {
      try {
        var cmd2 = "docker exec " + containerName + " openclaw gateway call " + method + " --url ws://127.0.0.1:20000 --token " + token + " --params '" + paramsStr + "' --timeout " + (timeoutMs || 15000) + " 2>/dev/null";
        var out2 = execSync(cmd2, { timeout: (timeoutMs || 15000) + 5000 }).toString().trim();
        var lines = out2.split("\n");
        var jsonStart = lines.findIndex(function(l) { return l.trim().startsWith("{"); });
        if (jsonStart >= 0) { resolve(JSON.parse(lines.slice(jsonStart).join("\n"))); }
        else reject(new Error("No JSON in output"));
      } catch(e2) { reject(new Error(e2.message || "Gateway call failed")); }
    }
  });
}
function getContainerName(email) { var dep = db.prepare("SELECT * FROM deployments WHERE email=?").get(email); if (!dep) return null; return "claw-" + email.replace(/[^a-zA-Z0-9]/g, "-") + "-" + dep.userId; }
app.post("/api/chat/send", auth, async (req, res) => { try { var cn = getContainerName(req.user.email); if (!cn) return res.status(404).json({ error: "Bot not found" }); var key = req.body.sessionKey || "agent:main:web-" + Date.now(); var idKey = "msg-" + Date.now() + "-" + Math.random().toString(36).slice(2,8); var result = await gatewayRPC(cn, "chat.send", { sessionKey: key, message: req.body.message, idempotencyKey: idKey }, 5000); res.json({ success: true, sessionKey: key, runId: result.runId || idKey }); } catch(e) { res.status(500).json({ error: e.message }); } });
app.get("/api/chat/history", auth, async (req, res) => { try { var cn = getContainerName(req.user.email); if (!cn) return res.status(404).json({ error: "Bot not found" }); var result = await gatewayRPC(cn, "chat.history", { sessionKey: req.query.sessionKey || "agent:main:main" }, 10000); res.json(result); } catch(e) { res.status(500).json({ error: e.message }); } });
app.get("/api/chat/sessions", auth, async (req, res) => { try { var cn = getContainerName(req.user.email); if (!cn) return res.status(404).json({ error: "Bot not found" }); var result = await gatewayRPC(cn, "sessions.list", {}, 10000); res.json(result); } catch(e) { res.status(500).json({ error: e.message }); } });
app.get("/api/chat/health", auth, async (req, res) => { try { var cn = getContainerName(req.user.email); if (!cn) return res.status(404).json({ error: "Bot not found" }); var result = await gatewayRPC(cn, "health", {}, 10000); res.json(result); } catch(e) { res.status(500).json({ error: e.message }); } });


app.post("/api/save-api-key", authenticateToken, async (req, res) => {
  const { provider, apiKey } = req.body;
  const email = req.user.email;
  
  if (!provider || !apiKey) {
    return res.json({ success: false, error: "プロバイダーとAPIキーが必要です" });
  }
  
  try {
    const containerName = `claw-${email.replace(/[^a-z0-9]/gi, "-")}`;
    
    // auth-profiles.jsonを更新
    const profileKey = `${provider}:default`;
    const updateScript = `
      import json
      with open('/home/clawuser/.openclaw/agents/main/agent/auth-profiles.json','r') as f:
        config = json.load(f)
      config['profiles']['${profileKey}'] = {
        'type': 'api_key',
        'provider': '${provider}',
        'key': '${apiKey}'
      }
      if 'lastGood' not in config:
        config['lastGood'] = {}
      config['lastGood']['${provider}'] = '${profileKey}'
      with open('/home/clawuser/.openclaw/agents/main/agent/auth-profiles.json','w') as f:
        json.dump(config, f, indent=2)
      print('OK')
    `;
    
    const result = await execAsync(`docker exec ${containerName} python3 -c "${updateScript}"`);
    
    if (result.stdout.includes('OK')) {
      res.json({ success: true });
    } else {
      res.json({ success: false, error: "設定の保存に失敗しました" });
    }
  } catch (err) {
    console.error('Save API key error:', err);
    res.json({ success: false, error: err.message });
  }
});



app.get("/api/get-configured-apis", authenticateToken, async (req, res) => {
  const email = req.user.email;
  
  try {
    const containerName = `claw-${email.replace(/[^a-z0-9]/gi, "-")}`;
    
    // auth-profiles.jsonを取得
    const result = await execAsync(`docker exec ${containerName} cat /home/clawuser/.openclaw/agents/main/agent/auth-profiles.json`);
    const config = JSON.parse(result.stdout);
    
    const apis = [];
    if (config.profiles) {
      for (const [key, profile] of Object.entries(config.profiles)) {
        const provider = profile.provider;
        let name = provider === 'anthropic' ? 'Anthropic Claude' : 
                   provider === 'openai' ? 'OpenAI GPT' : 
                   provider === 'google' ? 'Google Gemini' : provider;
        
        const keyPreview = profile.key ? profile.key.substring(0, 8) + '***' : '';
        
        apis.push({ provider, name, keyPreview });
      }
    }
    
    res.json({ success: true, apis });
  } catch (err) {
    console.error('Get APIs error:', err);
    res.json({ success: false, error: err.message });
  }
});


app.get("/api/test-endpoint", (req, res) => {
  res.json({ success: true, message: "Test endpoint works!" });
});

app.listen(3000, "0.0.0.0", () => { console.log("EasyClaw API running on port 3000"); console.log("Stripe:", STRIPE_SECRET_KEY ? "configured" : "NOT configured"); });
