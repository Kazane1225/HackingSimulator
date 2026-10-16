# HackLab — セキュリティ学習用ハッキングシミュレータ

Web の代表的な脆弱性を「攻撃者の視点」で体験し、仕組みと正しい対策を学ぶための教材です。

- 10 個の脆弱性ラボ × 5 段階のセキュリティレベル
- ヒントは 3 段階で 1 つずつ開けます（Lv5 は 2 段階）。解答はクリア後に解放。ラボごとの解説・サーバー側の疑似コード付き
- 各ラボに OWASP Top 10 / CWE の分類と参考資料へのリンク、ラボ共通の**用語集**（`#/glossary`）
- スマホ表示に対応（ラボ切替は上部のタブ、標的 / Proxy / ヒントはタブで切替）
- **脆弱な「サーバー」はすべてブラウザ内でシミュレート**されています。実際のサーバーやネットワークへは一切アクセスしないため、安全に遊べて GitHub Pages（静的ホスティング）でもそのまま動きます

> ⚠️ ここで学んだ技術を、許可なく実在のシステムに使うことは違法です（不正アクセス禁止法など）。必ず自分の環境や許可された演習環境でのみ使ってください。

## ラボ一覧

| ラボ | 目標 | 学べること |
|---|---|---|
| 🗄️ SQL インジェクション | パスワードを知らずに admin でログイン | 文字列連結クエリの危険性、ブラックリストの限界、プレースホルダ |
| 💬 XSS | コメント欄から `alert()` を実行 | イベントハンドラ、非冪等なフィルタ、出力エンコード |
| 🖥️ OS コマンドインジェクション | ping ツールから `flag.txt` を読む | シェルのメタ文字、コマンド置換、シェルを介さない実行 |
| 📂 パストラバーサル | 公開フォルダを脱出して `/etc/passwd` を読む | `../` の亜種、URL エンコード、正規化後の検証 |
| 🏦 CSRF | 被害者に攻撃者宛ての送金をさせる | 自動送信フォーム、Referer 検証の穴、同期トークンと SameSite |
| 🪪 IDOR | Alice のまま Bob の注文情報を読む | オブジェクト単位の認可、クライアント値の信用、旧 API の認可漏れ |
| 🔑 認証・セッション管理 | admin のログイン状態を取得 | 弱いパスワード、ユーザー列挙、セッション固定、MFA 回復フロー |
| 🎟️ JWT | 管理者トークンを偽造 | `alg:none`、弱い鍵、署名未検証、`kid` の悪用 |
| 🖧 SSRF | 内部メタデータを取得 | localhost、IP 表記ゆれ、リダイレクト、名前解決後の検証 |
| 📤 ファイルアップロード | 実行可能な内容を保存 | 二重拡張子、偽 MIME、ポリグロット、安全な再エンコード |

## セキュリティレベル

| レベル | 内容 |
|---|---|
| Lv1 | 防御なし |
| Lv2〜Lv4 | 少しずつ強化される「不完全な防御」。前のレベルの手口は通用しません |
| Lv5 | **正しい実装（Impossible）**。突破不可能で、なぜ安全なのかを学ぶためのレベルです |

各レベルで見られるもの:

- **ヒント** — いつでも表示
- **サーバー側コード** — そのレベルの防御の疑似コード。穴を探すコードレビューの練習に
- **解答** — そのレベルをクリアすると解放（Lv5 は Lv4 クリアで解説が読めます）
- **解説** — 脆弱性の仕組みと根本対策

進捗はブラウザの localStorage に保存されます。

## 実行方法

### Docker（推奨）

```bash
docker compose up -d --build
```

http://localhost:8080 を開きます。ポートを変える場合は `HACKLAB_PORT` を指定します。

```bash
HACKLAB_PORT=8088 docker compose up -d --build        # macOS / Linux
$env:HACKLAB_PORT=8088; docker compose up -d --build  # Windows PowerShell
```

停止は `docker compose down` です。

### Node.js で開発

Node.js 22 以上が必要です。

```bash
npm install
npm run dev        # 開発サーバー http://localhost:5173
npm run test:labs  # 全ラボのレベル設計を検証
npm run build      # dist/ に本番ビルド
```

## GitHub Pages へのデプロイ

`.github/workflows/deploy.yml` が `main` への push ごとにテスト（ラボのテスト・型チェック・ビルド・E2E）→ ビルド → デプロイを行います。テストが 1 つでも失敗すると公開されません。

1. このリポジトリを GitHub に push する
2. リポジトリの **Settings → Pages → Build and deployment → Source** を **GitHub Actions** にする
3. Actions の完了後、`https://<ユーザー名>.github.io/<リポジトリ名>/` で公開されます

ビルドは相対パス（`base: "./"`）、ルーティングはハッシュ方式（`#/lab/sqli`）なので、サブパス配信でも追加設定は不要です。

## テスト

`npm run test:labs` は各ラボについて次を自動で確認します（Docker ビルドと CI でも実行されます）。

- Lv1〜4 がそれぞれの想定解法で突破できる
- 各レベルが直前のレベルの解法を防ぐ
- Lv5 がどの解法でも突破できない
- 普通の入力ではクリア扱いにならない

### E2E テスト

画面を通した動作は Playwright で確認します（Chromium。デスクトップとスマホ幅の 2 プロジェクト）。

```bash
npx playwright install chromium   # 初回のみ
npm run test:e2e                  # ビルド → preview 起動 → 実行
npm run typecheck:e2e             # e2e の型チェック
```

確認内容: XSS が sandbox 内で実際に発火したときだけクリアになること／進捗の保存と壊れたデータからの復旧／Intercept → 改ざん → Forward の流れ／ヒントの段階表示と解答のロック／スマホ幅でのペイン切替と横はみ出しがないこと。CI では PR ごとと、`main` へのデプロイ前に実行されます。

```
e2e/
├── specs/       # テスト本体（*.mobile.spec.ts はスマホ幅で実行）
├── pages/       # Page Object（LabPage, Sidebar, apps/ に標的アプリごとの操作）
├── data/        # 期待値・テストデータ（ラベル、ペイロード、ヒント数、ルートなど）
├── fixtures/    # Page Object を差し込んだ test 拡張
└── support/     # localStorage 操作などの補助
```

## プロジェクト構成

```
├── src/
│   ├── labs/              # 各ラボのシミュレーションロジックと教材テキスト
│   │   ├── types.ts       # ラボ / レベル / 結果の共通型
│   │   ├── sqli.ts        # 簡易 SQL 評価器つきログイン
│   │   ├── xss.ts         # サニタイズ処理と実行ベクター判定
│   │   ├── cmdi.ts        # 疑似シェルと仮想ファイルシステム
│   │   ├── pathtraversal.ts
│   │   ├── csrf.ts        # 攻撃ページの解析と銀行側の検証
│   │   ├── idor.ts        # 注文 API のオブジェクト単位認可
│   │   ├── auth.ts        # 認証・セッション管理
│   │   ├── jwt.ts         # JWT の解析と署名検証
│   │   ├── ssrf.ts        # URL と内部アドレスの検証
│   │   ├── upload.ts      # ファイル種別と保存方法の検証
│   │   └── index.ts       # ラボ一覧
│   ├── components/        # 画面（ホーム、ラボ、XSS プレビュー）
│   ├── progress.ts        # クリア状況の保存
│   └── App.tsx
├── scripts/test-labs.ts   # レベル設計の検証
├── e2e/                   # Playwright の E2E テスト
├── playwright.config.ts
├── Dockerfile             # Node でビルド → nginx で配信
├── docker-compose.yml
├── nginx.conf
└── .github/workflows/     # checks.yml（共通のテスト）を ci.yml（PR）と deploy.yml（main）から呼び出す
```

### XSS ラボの安全性について

XSS ラボでは、入力したペイロードを `sandbox="allow-scripts"`（same-origin なし）の iframe 内で実際に実行します。iframe は親ページとは別オリジン扱いになるため、ペイロードから本体ページの DOM や localStorage には触れられません。`alert()` などは iframe 内で差し替えられており、呼ばれると親ページに通知してクリア判定されます。

## ラボを追加するには

1. `src/labs/` に `Lab` 型（`src/labs/types.ts`）を満たすモジュールを作る（Lv1〜4 の解法を `exploits` に含める）
2. `src/labs/index.ts` の `LABS` に追加する
3. `src/components/labUI.tsx` の `LAB_UI` に、同じ id の画面定義を追加する
4. `npm run test:labs` で確認する（`exploits` からレベル設計を自動検証し、`LAB_UI` の登録漏れも検出します）
