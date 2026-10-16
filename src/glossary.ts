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
      "何度適用しても結果が変わらない処理を『冪等』と呼びます。1 回だけ除去する処理は、除去の結果として禁止語が再生成され得ます（例: `oorr` → `or`）。",
    labs: ["sqli", "xss", "path"],
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
      "セッションごとに発行するランダムな値。リクエストに含めさせてサーバーが『値を厳密に』照合します。存在確認だけでは意味がありません。",
    labs: ["csrf"],
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
];
