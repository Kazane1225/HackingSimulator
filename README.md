# HackLab — セキュリティ学習用ハッキングシミュレータ

Web の代表的な脆弱性を「攻撃者の視点」で体験し、仕組みと正しい対策を学ぶための教材です。

- 5 つの脆弱性ラボ × 5 段階のセキュリティレベル
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

`.github/workflows/deploy.yml` が `main` への push ごとにテスト → ビルド → デプロイを行います。

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
│   │   └── index.ts       # ラボ一覧
│   ├── components/        # 画面（ホーム、ラボ、XSS プレビュー）
│   ├── progress.ts        # クリア状況の保存
│   └── App.tsx
├── scripts/test-labs.ts   # レベル設計の検証
├── Dockerfile             # Node でビルド → nginx で配信
├── docker-compose.yml
├── nginx.conf
└── .github/workflows/deploy.yml
```

### XSS ラボの安全性について

XSS ラボでは、入力したペイロードを `sandbox="allow-scripts"`（same-origin なし）の iframe 内で実際に実行します。iframe は親ページとは別オリジン扱いになるため、ペイロードから本体ページの DOM や localStorage には触れられません。`alert()` などは iframe 内で差し替えられており、呼ばれると親ページに通知してクリア判定されます。

## ラボを追加するには

1. `src/labs/` に `Lab` 型（`src/labs/types.ts`）を満たすモジュールを作る（Lv1〜4 の解法を `exploits` に含める）
2. `src/labs/index.ts` の `LABS` に追加する
3. `src/components/labUI.tsx` の `LAB_UI` に、同じ id の画面定義を追加する
4. `npm run test:labs` で確認する（`exploits` からレベル設計を自動検証し、`LAB_UI` の登録漏れも検出します）
