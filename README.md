# EasyClaw

**完全無料・VPS不要のローカルAIチャットアプリ**

Ollama + OpenClaw を使って、自分のPCだけで動くAIアシスタントを構築できます。コーディングエージェント、ブラウザ自動操作、3モデルオーケストレーションを搭載。

## 特徴

- **完全ローカル** — インターネット不要、データは自分のPCに保存
- **3モデル自動切替** — タスクに応じて最適なLLMを自動選択
  - `llama3.2` — 一般チャット（高速）
  - `qwen2.5-coder:7b` — コーディング特化
  - `deepseek-r1:14b` — 深い推論・分析
- **コーディングエージェント** — ファイル作成/編集/検索/コマンド実行を自律的に実行
- **ブラウザエージェント** — AIがChromeを操作してWeb情報を取得
- **Claude Code風UI** — コンパクトなプログレス表示、Markdown対応

## 必要環境

- **Node.js** v22以上
- **Ollama** ([ollama.com](https://ollama.com))
- **OpenClaw** (`npm install -g openclaw`)

## セットアップ

```bash
# 1. クローン
git clone https://github.com/tsurutatsuji/easyclaw.git
cd easyclaw

# 2. 依存インストール
npm install

# 3. Ollamaモデルをダウンロード
ollama pull llama3.2
ollama pull qwen2.5-coder:7b
ollama pull deepseek-r1:14b

# 4. 起動
npm start
```

ブラウザで `http://localhost:3000` を開き、アカウント登録 → セットアップ → チャット開始。

## アーキテクチャ

```
[Browser] ←→ [Express Server :3000] ←→ [Ollama :11434]
                    ↕
            [OpenClaw Gateway :18789]
                    ↕
            [Chrome (Playwright)]
```

| コンポーネント | 役割 |
|---------------|------|
| `server.js` | APIサーバー、LLMオーケストレーター、エージェントループ |
| `public/chat.html` | チャットUI（SSEストリーミング） |
| `public/setup.html` | 初期セットアップウィザード |
| `public/lp.html` | ランディングページ |

## コーディングエージェント

チャットで「〜を作って」と頼むと、自動的にコーディングエージェントが起動します。

### 利用可能なツール

| ツール | 説明 |
|--------|------|
| `file_write` | ファイル作成・上書き |
| `file_edit` | ファイル部分編集（search/replace） |
| `file_read` | ファイル読み取り（行番号付き） |
| `list_files` | ディレクトリツリー表示 |
| `grep` | コード内検索（regex対応） |
| `shell` | コマンド実行 |

ワークスペース: `~/easyclaw-workspace/`

## ブラウザエージェント

URLを含むメッセージを送ると、AIがChromeを起動してページを操作します。

```
「https://example.com を開いて内容を教えて」
```

## 技術スタック

- **Backend**: Express.js, better-sqlite3, WebSocket
- **Frontend**: Vanilla JS (SPA), SSE streaming
- **LLM**: Ollama (ローカル)
- **Browser**: OpenClaw + Playwright
- **Auth**: JWT + OTP (email認証)

## ライセンス

ISC
