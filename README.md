# HackLab — セキュリティ学習用ハッキングシミュレータ

Web の代表的な脆弱性を「攻撃者の視点」で体験し、仕組みと正しい対策を学ぶための教材です。

- 15 個の脆弱性ラボ × 5 段階のセキュリティレベル。ダッシュボードに**推奨順**と、OWASP Top 10:2021 のカバー状況を表示
- ヒントは 3 段階で 1 つずつ開けます（Lv5 は 2 段階）。解答はクリア後に解放。ラボごとの解説・サーバー側の疑似コード付き
- 各ラボに OWASP Top 10 / CWE の分類と参考資料へのリンク、ラボ共通の**用語集**（`#/glossary`）
- スマホ表示に対応（ラボ切替は上部のタブ、標的 / Proxy / ヒントはタブで切替）
- **脆弱な「サーバー」はすべてブラウザ内でシミュレート**されています。実際のサーバーやネットワークへは一切アクセスしないため、安全に遊べて GitHub Pages（静的ホスティング）でもそのまま動きます

> ⚠️ ここで学んだ技術を、許可なく実在のシステムに使うことは違法です（不正アクセス禁止法など）。必ず自分の環境や許可された演習環境でのみ使ってください。

## ラボ一覧

| ラボ | 目標 | 学べること |
|---|---|---|
| 🗄️ SQL インジェクション | パスワードを知らずに admin になる／ユーザー表を奪う | 文字列連結、クオートエスケープの穴、隠しパラメータ、UNION |
| 💬 XSS | コメント欄から `alert()` を実行 | タグ除去、属性コンテキスト、JS 文字列、出力エンコード |
| 🖥️ OS コマンドインジェクション | ping ツールから `flag.txt` を読む | メタ文字、クオート囲みの限界、シェルを介さない実行 |
| 📂 パストラバーサル | 公開フォルダを脱出して秘密ファイルを読む | `../` 除去、拡張子許可リスト、readme からの連鎖、path.join |
| 🏦 CSRF | 被害者に攻撃者宛ての送金をさせる | POST 必須、セッション未紐づけトークン、CRLF による Cookie 注入、SameSite |
| 🪪 IDOR | Alice のまま Bob の注文情報を読む | オブジェクト単位の認可、関連 ID の漏洩、GraphQL 開発タブ |
| 🔑 認証・セッション管理 | admin のログイン状態を取得 | 回数制限のない辞書攻撃、X-Forwarded-For を信用したロック、予測可能なリセット、MFA コードのデバッグ漏洩 |
| 🎟️ JWT | 管理者トークンを偽造 | `alg:none`、弱い HMAC 鍵、アルゴリズム混同、`jku` からの鍵取得 |
| 🖧 SSRF | 内部メタデータを取得 | localhost、ホスト許可リスト、リダイレクト先の別表記、名前解決後の検証 |
| 📤 ファイルアップロード | 実行可能な内容を保存 | 二重拡張子、ポリグロット、`.phtml` / `.htaccess`、安全な再エンコード |
| 🔐 暗号の失敗 | 保管庫のトークンからカード番号を復元 | Base64、ソースに書いた XOR、署名対象の外 |
| ⚙️ 設定ミス | 本番に残った入口から秘密を読む | デバッグ、末尾スラッシュ、Actuator、公開された `.env` |
| 📦 古いコンポーネント | 弱いライブラリ経由で秘密ファイルを読む | 検査後の復号、二重符号化、残った旧エンジン |
| ✍️ 署名なし更新 | 更新マニフェストを admin として適用 | 署名なし、鍵のないハッシュ、ソースの HMAC 鍵、署名対象外の role |
| 📋 ログの穴 | 監視が誤認する記録を残す、または記録されない操作を実行 | 改行、復帰文字、JSON の破壊、記録されない隠しパラメータ |

推奨順は **インジェクション → アクセス制御 → 認証 → リクエストとファイル → 暗号・設定・記録** です。OWASP Top 10:2021 は専用ラボでカバーし、A04 はファイルアップロードが隣接です。

## セキュリティレベル

| レベル | 内容 |
|---|---|
| Lv1 | 防御なし |
| Lv2 | 最初の、よくある不完全な防御 |
| Lv3〜Lv4 | **別の種類**の不完全な防御（エスケープ、許可リスト、別経路、別コンテキストなど）。禁止リストを厚くするだけではない。前のレベルの手口は通用しません |
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

## 実サーバー環境（開発中）

ブラウザ内の疑似サーバーではなく、**実際に動く脆弱なサーバー**を相手にするための環境です（`develop_real_hacking_simulator` ブランチで開発中）。既存の静的版（上の `docker-compose.yml`）には影響しません。

```bash
npm run real:up     # docker compose -f docker-compose.real.yml up -d --build
npm run real:down
npm run server:test # サーバーの単体テスト（先に cd server && npm install）
```

http://localhost:8080 を開くと、フロントと同じ origin の `/api/` 経由でラボサーバーに届きます（動作確認: `/api/healthz`、`/api/info`）。

全 15 ラボに実サーバー版があり、防御バーに「シミュレート / 実サーバー」の切替が出ます。「実サーバー」を選ぶと、Proxy は標的アプリの本物の HTTP（例: `POST /api/sqli/lv1/login`）を表示して送ります。レベルはパスに載り、応答はステータス・ヘッダ・本文です。成否はその本文から読みます。採点用の `POST /api/<ラボ>/run` はありません。

| ラボ | 実サーバー版の中身 |
|---|---|
| SQL インジェクション | 本物の SQLite（`node:sqlite`）でクエリを実行。構文エラー、演算子の優先順位、UNION の列数制約は DB 自身の挙動 |
| XSS | サーバーが各レベルの出力処理（タグ除去、属性・JS 文字列コンテキスト、エンコード）を行った HTML を返し、ブラウザの iframe 内での実行で成否を判定（サーバーは投稿されたスクリプトを実行しない） |
| OS コマンドインジェクション | 本物の `/bin/sh` でコマンドを実行。クオートや `$(...)` の扱いはシェルそのもの（`ping` だけは外向き通信がないため代替スクリプト） |
| パストラバーサル | 本物の `node:fs` / `node:path` で、コンテナ内の固定フィクスチャ木（公開フォルダ + 設置済みの秘密ファイル）を読む。外側へは出られない |
| CSRF | 本物の HTTP（loopback の銀行サーバー）、Set-Cookie / SameSite の解釈、CRLF によるヘッダ注入、HMAC トークン |
| IDOR | 本物の SQLite と、オブジェクト単位の認可チェック。GraphQL 開発タブは本物のパーサ |
| 認証・セッション管理 | 本物の scrypt（Lv5）、辞書攻撃と X-Forwarded-For によるロック回避、予測可能なリセットトークン、RFC 6238 の TOTP とデバッグ漏洩 |
| JWT | 本物の HMAC / RSA 署名（`node:crypto`）、`alg:none`、アルゴリズム混同、`jku` による鍵取得 |
| SSRF | 本物の `node:http` と `new URL`。内部メタデータサービスは loopback に設置済み。名前解決は明示的なテーブルのみ（外部へは出ない） |
| ファイルアップロード | 一時ディレクトリへ実際に保存（実行はしない）。Apache の拡張子→ハンドラ判定と `.htaccess` を再現 |
| 暗号の失敗 | サーバーが Base64 と XOR を実際に戻す。Lv5 の鍵はこのプロセスに無い |
| 設定ミス | `lab-files/misconf` の実ファイルを返す。リクエストの path はファイルシステムへ結合しない |
| 古いコンポーネント | 弱いパス解釈のあと、秘密は `lab-files/deps/secret` だけを読む。渡されたパスはファイルシステムへ渡さない |
| 署名なし更新 | SHA-256 と HMAC-SHA256（`node:crypto`）。Lv5 の鍵はプロセス内だけで、応答に出さない |
| ログの穴 | リクエストごとの記録文字列。改行と JSON の壊れ方、記録されない `op`。ディスクへは書かない |

実サーバーが無い環境（GitHub Pages など）では切替自体が表示されず、従来どおり動きます。開発時は `npm run dev` が `/api` を `http://localhost:3000`（`HACKLAB_SERVER` で変更可）へ中継します。サーバー単体は `cd server && npm install && npm run build && npm start` で起動できます。

起動中のスタックに対して、疑似版の想定解法が実サーバーでも通ることを確認するには `npm run test:real`（`HACKLAB_URL` で接続先を変更可、既定 `http://localhost:8080`）を実行します。

| サービス | 役割 |
|---|---|
| `gateway` | 静的フロント + `/api/` のリバースプロキシ。唯一ポートを公開 |
| `lab-server`（[server/](./server)） | 意図的に脆弱なラボの実体。ラボは `registerLab()` で追加 |

`lab-server` は内部専用ネットワーク（外向き通信なし）、ポート非公開、非 root、読み取り専用ルート FS、全 capability 削除、CPU / メモリ / プロセス数制限で隔離しています。新しい標的を足すときもこの方針を保ってください。**このスタックはローカル利用が前提で、インターネットへ公開しないでください**（デプロイ方針は未定）。

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
│   ├── curriculum.ts      # 推奨順と OWASP Top 10 のカバー状況
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
