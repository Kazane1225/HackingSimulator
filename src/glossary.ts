export interface GlossaryTerm {
  term: string;
  /** Alternative names / English spelling, also searched. */
  aliases?: string[];
  description: string;
  /** Lab ids where the term is most relevant. */
  labs?: string[];
}

export const GLOSSARY: GlossaryTerm[] = [
  {
    term: "ペイロード",
    aliases: ["payload"],
    description: "攻撃のためにアプリへ送り込む入力データ。`' OR '1'='1` や `<script>…</script>` など。",
  },
  {
    term: "インジェクション",
    aliases: ["injection"],
    description:
      "ユーザー入力が『データ』ではなく『命令の一部』として解釈されてしまう脆弱性の総称。SQL、OS コマンド、HTML などが対象になります。",
    labs: ["sqli", "xss", "cmdi"],
  },
  {
    term: "ブラックリスト",
    aliases: ["denylist", "blocklist"],
    description:
      "『禁止するもの』を列挙して防ぐ方式。想定外の書き方や別表現で回避されやすく、根本対策にはなりません。",
    labs: ["sqli", "xss", "cmdi", "path"],
  },
  {
    term: "ホワイトリスト",
    aliases: ["allowlist", "許可リスト"],
    description: "『許可するもの』だけを通す方式。ブラックリストより堅牢で、入力検証の基本です。",
    labs: ["cmdi", "path"],
  },
  {
    term: "非冪等フィルタ",
    aliases: ["idempotent", "単一パス"],
    description:
      "何度適用しても結果が変わらない処理を『冪等』と呼びます。1 回だけ除去する処理は、除去の結果として禁止語が再生成され得ます（例: `....//` から `../`）。",
    labs: ["path"],
  },
  {
    term: "出力コンテキスト",
    aliases: ["attribute injection", "属性インジェクション"],
    description:
      "同じ文字列でも、HTML 本文・属性値・JavaScript 文字列では必要なエスケープが違います。ある場所向けの対策が、別の埋め込み先では無効になります。",
    labs: ["xss"],
  },
  {
    term: "アルゴリズム混同",
    aliases: ["algorithm confusion", "alg:none"],
    description:
      "JWT の header.alg をサーバーが信用すると、RS256 用の公開鍵を HS256 の HMAC 秘密として使わせるなどのすり替えが起きます。検証アルゴリズムはサーバー側で固定します。",
    labs: ["jwt"],
  },
  {
    term: "プレースホルダ",
    aliases: ["プリペアドステートメント", "prepared statement", "バインド"],
    description:
      "SQL の構造と値を分離して DB に渡す仕組み。入力は常に『値』として扱われ、SQL 構文として解釈されません。SQL インジェクションの根本対策です。",
    labs: ["sqli"],
  },
  {
    term: "エスケープ / 出力エンコード",
    aliases: ["escape", "encoding", "実体参照"],
    description:
      "特殊文字を無害な表現に変換すること（例: `<` → `&lt;`）。出力先（HTML 本文、属性、JS、URL）ごとに適切な方式を使います。",
    labs: ["xss"],
  },
  {
    term: "サニタイズ",
    aliases: ["sanitize"],
    description:
      "入力から危険な部分を除去・無害化すること。範囲が曖昧な言葉で、除去型は回避されやすいため、出力時のエンコードを基本にします。",
    labs: ["xss"],
  },
  {
    term: "イベントハンドラ",
    aliases: ["onerror", "onload", "ontoggle"],
    description:
      "HTML 要素の属性（`onerror=…` など）に書く JavaScript。`<script>` タグを使わなくてもスクリプトを実行できます。",
    labs: ["xss"],
  },
  {
    term: "サンドボックス",
    aliases: ["sandbox", "iframe"],
    description:
      "実行環境を隔離して被害を封じ込める仕組み。このアプリの XSS ラボは `sandbox` 属性付き iframe で、ペイロードが親ページに触れないようにしています。",
    labs: ["xss"],
  },
  {
    term: "同一オリジンポリシー",
    aliases: ["same-origin policy", "SOP", "オリジン"],
    description:
      "スキーム・ホスト・ポートが同じ場合のみ、ページ同士がデータを読み書きできるブラウザの制限。ただし別サイトへのリクエスト『送信』は止めないため、CSRF が成立します。",
    labs: ["xss", "csrf"],
  },
  {
    term: "シェル / メタ文字",
    aliases: ["shell", "metacharacter"],
    description:
      "コマンドを解釈するプログラム。`;` `&&` `|` 改行 `$(…)` などの特別な意味を持つ文字（メタ文字）で、複数のコマンドを連結できます。",
    labs: ["cmdi"],
  },
  {
    term: "コマンド置換",
    aliases: ["command substitution"],
    description: "`$(cmd)`（古い書式ではバッククォート囲み）の形で、コマンドの出力をその場に埋め込むシェルの構文。",
    labs: ["cmdi"],
  },
  {
    term: "引数配列での実行",
    aliases: ["execFile", "spawn", "argv"],
    description:
      "シェルを介さず、プログラムと引数を配列で直接渡して起動する方法。メタ文字が解釈されないため、コマンドインジェクションの根本対策です。",
    labs: ["cmdi"],
  },
  {
    term: "パストラバーサル",
    aliases: ["directory traversal", "ディレクトリトラバーサル"],
    description: "`../` で基準ディレクトリより上へ遡り、公開範囲外のファイルを読み書きする攻撃。",
    labs: ["path"],
  },
  {
    term: "URL エンコード",
    aliases: ["パーセントエンコーディング", "percent-encoding"],
    description:
      "`%2e`（`.`）や `%2f`（`/`）のように、文字を `%` + 16 進数で表す方式。検証後にデコードされると、検証をすり抜けられます。",
    labs: ["path"],
  },
  {
    term: "正規化",
    aliases: ["canonicalization", "normalize"],
    description:
      "同じ対象を指す複数の表記を 1 つの標準形に揃えること（例: `a/../b` → `b`）。検証は『デコードと正規化の後』に行います。",
    labs: ["path"],
  },
  {
    term: "セッション / Cookie",
    aliases: ["session", "cookie"],
    description:
      "ログイン状態をサーバーが識別する仕組み。ブラウザは Cookie を送信先サイトへ自動的に付けるため、CSRF の前提になります。",
    labs: ["csrf"],
  },
  {
    term: "SameSite",
    aliases: ["SameSite=Strict", "SameSite=Lax"],
    description:
      "別サイトからのリクエストに Cookie を付けるかを制御する属性。`Strict` ではクロスサイトで一切送られず、CSRF を大きく抑えられます。",
    labs: ["csrf"],
  },
  {
    term: "Referer",
    aliases: ["リファラ", "no-referrer"],
    description:
      "リクエスト元の URL を示すヘッダ。送られない場合があるため、これだけで CSRF 対策にはできません。",
    labs: ["csrf"],
  },
  {
    term: "CSRF トークン",
    aliases: ["synchronizer token", "同期トークン"],
    description:
      "セッションごとに発行するランダムな値。リクエストのトークンが『今のセッションに紐づく値』と一致するかまで見ます。発行済みかどうかだけ、あるいは別ユーザーのトークンを受け入れる実装では足りません。",
    labs: ["csrf"],
  },
  {
    term: "CRLF / ヘッダインジェクション",
    aliases: ["HTTP response splitting", "Set-Cookie 注入", "%0d%0a"],
    description:
      "CR（\\r）と LF（\\n）は HTTP ヘッダの区切りです。ユーザー入力を Set-Cookie などに連結して改行を除去しないと、追加のヘッダ（別の Cookie など）を注入できます。",
    labs: ["csrf"],
  },
  {
    term: "認証 / 認可",
    aliases: ["authentication", "authorization"],
    description:
      "認証は『誰であるか』を確認する処理、認可は『その人が対象の操作をしてよいか』を確認する処理。ログイン済みでも、他人のデータへの認可は別途必要です。",
    labs: ["idor", "auth", "jwt"],
  },
  {
    term: "IDOR",
    aliases: ["Insecure Direct Object Reference", "オブジェクトレベル認可"],
    description:
      "URL や API の ID を変更したとき、サーバーが対象データへの権限を確認せず、他人のデータを読み書きできる脆弱性。",
    labs: ["idor"],
  },
  {
    term: "ブルートフォース / パスワードスプレー",
    aliases: ["brute force", "password spraying", "辞書攻撃"],
    description:
      "多数のパスワードを試す攻撃。パスワードスプレーは少数のありがちなパスワードを多数のアカウントへ試し、単純なロックアウトを避けます。",
    labs: ["auth"],
  },
  {
    term: "セッション固定",
    aliases: ["session fixation"],
    description:
      "攻撃者が事前に知っているセッション ID を被害者に使わせ、ログイン後も ID が更新されない場合にそのログイン状態を奪う攻撃。",
    labs: ["auth"],
  },
  {
    term: "MFA",
    aliases: ["多要素認証", "Multi-Factor Authentication"],
    description:
      "知識・所持・生体など異なる種類の要素を複数使う認証。デバッグ応答や回復フローが弱いと、通常ログインの MFA を迂回されます。",
    labs: ["auth"],
  },
  {
    term: "デバッグ情報の漏洩",
    aliases: ["verbose error", "X-Debug"],
    description:
      "開発用の詳細エラーやメールプレビューを本番に残すと、MFA コードや内部パスなどの秘密が応答に出ます。認証失敗時ほど出してはいけません。",
    labs: ["auth"],
  },
  {
    term: "HMAC",
    aliases: ["HS256", "HMAC-SHA256"],
    description:
      "共有秘密鍵によるメッセージ認証。JWT の HS256 は header.payload を HMAC-SHA256 し、秘密鍵が弱いとオフラインで署名し直せます。",
    labs: ["jwt"],
  },
  {
    term: "jku",
    aliases: ["JWKS", "JSON Web Key Set"],
    description:
      "JWT header が指す鍵セットの URL。サーバーが任意の jku から鍵を取ると、攻撃者の JWKS（oct 鍵を含む）で署名を通せてしまいます。",
    labs: ["jwt"],
  },
  {
    term: "JWT",
    aliases: ["JSON Web Token", "alg", "kid"],
    description:
      "header.payload.signature からなるトークン形式。payload は暗号化されておらず、サーバーによる署名・アルゴリズム・クレームの検証が必要です。",
    labs: ["jwt"],
  },
  {
    term: "SSRF",
    aliases: ["Server-Side Request Forgery", "サーバーサイドリクエストフォージェリ"],
    description:
      "サーバーの URL 取得機能を操作し、内部 API、localhost、クラウドメタデータなどへサーバー自身からリクエストさせる攻撃。",
    labs: ["ssrf"],
  },
  {
    term: "DNS Rebinding",
    aliases: ["DNS リバインディング", "名前解決"],
    description:
      "同じホスト名の DNS 応答を途中で外部 IP から内部 IP へ変える手口。検証時と接続時の名前解決がずれると SSRF 対策を回避されます。",
    labs: ["ssrf"],
  },
  {
    term: "マジックバイト / ポリグロット",
    aliases: ["magic bytes", "file signature", "polyglot"],
    description:
      "マジックバイトはファイル形式を示す先頭データ。ポリグロットは複数形式として解釈できるファイルで、先頭だけの検査を回避することがあります。",
    labs: ["upload"],
  },
  {
    term: "再エンコード",
    aliases: ["re-encode", "画像再構成"],
    description:
      "受け取った画像を完全にデコードし、新しい画像データとして保存し直すこと。元データに埋め込まれた不要な内容を引き継がないための対策です。",
    labs: ["upload"],
  },
  {
    term: "Proxy / Intercept",
    aliases: ["傍受", "Forward", "Burp"],
    description:
      "ブラウザとサーバーの間でリクエストを止めて書き換える道具。このアプリの Proxy ペインで、送信前に値を改ざんして Forward できます。",
  },
  {
    term: "多層防御",
    aliases: ["defense in depth"],
    description: "単独の対策に頼らず、入力検証・出力エンコード・権限制御などを重ねて被害を抑える考え方。",
  },
  {
    term: "最小権限",
    aliases: ["least privilege"],
    description: "プログラムやアカウントに、必要最小限の権限だけを与える原則。侵害されたときの被害を小さくします。",
    labs: ["cmdi", "path"],
  },
  {
    term: "OWASP Top 10",
    aliases: ["OWASP"],
    description: "Web アプリケーションで特に重大なリスクを 10 分類にまとめた、OWASP による定番の啓発文書。",
  },
  {
    term: "CWE",
    aliases: ["Common Weakness Enumeration"],
    description: "ソフトウェアの弱点（脆弱性の原因）を種類別に番号付けした一覧。例: CWE-89 は SQL インジェクション。",
  },
  {
    term: "符号化と暗号化",
    aliases: ["Base64", "encoding"],
    description: "Base64 は誰でも戻せます。固定の XOR や、ソースに書いた鍵も秘密ではありません。カード番号のような秘密は、認証付き暗号とアプリの外にある鍵で守ります。",
    labs: ["crypto"],
  },
  {
    term: "セキュリティ設定ミス",
    aliases: ["misconfiguration", "デバッグ", "Actuator"],
    description: "本番でデバッグや管理エンドポイントを有効にしたままにする、秘密ファイルを公開ディレクトリに含める、といった止め忘れです。",
    labs: ["misconf"],
  },
  {
    term: "脆弱なコンポーネント",
    aliases: ["outdated component", "依存関係"],
    description: "アプリ本体を直しても、古いライブラリが入力を別の規則で解釈すると穴が残ります。古い入口を消し、渡す値をファイル名だけに限定します。",
    labs: ["deps"],
  },
  {
    term: "完全性",
    aliases: ["integrity", "署名", "HMAC"],
    description: "データが改ざんされていないことの確認です。鍵のないハッシュや、署名対象の外にある項目は、書き換えた側が通ります。",
    labs: ["integrity"],
  },
  {
    term: "ログインジェクション",
    aliases: ["log injection", "ログ注入"],
    description: "改行や引用符をログへそのまま書くと、監視が読むイベントを偽れます。記録は実行した操作そのものにし、制御文字はエスケープします。",
    labs: ["logging"],
  },
];
