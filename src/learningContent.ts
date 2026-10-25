import type { CveReference, RemediationSpec } from "./labs/types";

type LearningContent = {
  remediation: RemediationSpec;
  cves: CveReference[];
};

const nvd = (id: CveReference["id"]) => `https://nvd.nist.gov/vuln/detail/${id}`;

export const LEARNING_CONTENT: Record<string, LearningContent> = {
  sqli: {
    remediation: {
      objective: "入力をSQL構文から完全に分離し、すべての可変値をバインドする",
      checklist: ["文字列連結を残さない", "隠しパラメータもプレースホルダ化する", "DB権限とエラー露出を最小化する"],
      reviewNote: "一部の列だけをバインドしても、連結された値が1つ残ればSQLインジェクションは成立します。",
    },
    cves: [{ id: "CVE-2023-34362", title: "MOVEit Transfer SQL injection", summary: "外部入力がSQLとして解釈され、認証回避やデータ窃取につながった実例です。", url: nvd("CVE-2023-34362"), relation: "same-class" }],
  },
  xss: {
    remediation: {
      objective: "出力先の文脈に合うエンコードを行い、危険なDOM APIを避ける",
      checklist: ["HTML・属性・JavaScript文脈を区別する", "信頼できるサニタイザを使う", "CSPとTrusted Typesを多層防御にする"],
      reviewNote: "タグ除去だけでは属性やJavaScript文字列の文脈を防げません。最終的な出力先で処理します。",
    },
    cves: [{ id: "CVE-2020-11022", title: "jQuery DOM manipulation XSS", summary: "サニタイズ済みに見えるHTMLがDOM操作で実行可能になる、mutation XSSに近い実例です。", url: nvd("CVE-2020-11022"), relation: "same-class" }],
  },
  cmdi: {
    remediation: {
      objective: "シェルを介さず、引数を配列として渡して許可値を検証する",
      checklist: ["execFile相当を使う", "実行ファイルを固定する", "引数の形式・長さ・実行時間を制限する"],
      reviewNote: "クォートで囲むだけではコマンド置換を防げない場合があります。シェル自体を経由しない設計が中心です。",
    },
    cves: [{ id: "CVE-2024-24576", title: "Rust std::process Windows argument injection", summary: "シェルを明示していなくてもWindowsのバッチ実行時に引数が再解釈されたBatBadButの実例です。", url: nvd("CVE-2024-24576"), relation: "same-class" }],
  },
  path: {
    remediation: {
      objective: "正規化後の実パスが許可ルート配下にあることを保証する",
      checklist: ["デコードと正規化を一度だけ行う", "basenameや拡張子だけに頼らない", "固定ルートとの包含関係を検証する"],
      reviewNote: "`../` の文字列除去は多重符号化や絶対パスを見落とします。解決後のパスで境界を確認します。",
    },
    cves: [{ id: "CVE-2021-41773", title: "Apache HTTP Server path traversal", summary: "パス正規化の不備からAlias外のファイル参照や、構成によってはコマンド実行に至った実例です。", url: nvd("CVE-2021-41773"), relation: "direct" }],
  },
  csrf: {
    remediation: {
      objective: "変更操作を推測不能なトークンと送信元検証で利用者セッションに結び付ける",
      checklist: ["トークンをセッションに紐付ける", "Origin/Refererを検証する", "SameSiteだけを唯一の防御にしない"],
      reviewNote: "POST化や固定トークンだけでは、攻撃元ページから同じ操作を再現できます。",
    },
    cves: [{ id: "CVE-2024-4994", title: "GitLab GraphQL mutation CSRF", summary: "状態変更GraphQL操作で送信元保護が不足し、被害者の権限で操作できた実例です。", url: nvd("CVE-2024-4994"), relation: "same-class" }],
  },
  idor: {
    remediation: {
      objective: "要求されたオブジェクトごとに、現在の主体が操作可能か検証する",
      checklist: ["検索条件にownerを含める", "関連IDやGraphQLでも同じ認可を通す", "推測困難なIDを認可の代わりにしない"],
      reviewNote: "画面でIDを隠してもAPIへ直接送れます。データ取得時に所有者・権限を強制します。",
    },
    cves: [{ id: "CVE-2019-15581", title: "GitLab private group IDOR", summary: "利用者が制御する識別子を通じ、権限のない非公開グループのメンバー情報を参照できた実例です。", url: nvd("CVE-2019-15581"), relation: "direct" }],
  },
  auth: {
    remediation: {
      objective: "認証・リセット・MFAの全経路を同じ強度で保護する",
      checklist: ["強いパスワードハッシュを使う", "リセットトークンを乱数・単回・短寿命にする", "MFA秘密やコードをログへ出さない"],
      reviewNote: "ログインだけを強化しても、パスワード再設定やMFAの迂回経路が弱ければ乗っ取られます。",
    },
    cves: [{ id: "CVE-2023-7028", title: "GitLab password reset account takeover", summary: "パスワード再設定メールを攻撃者側にも送れる不備からアカウント乗っ取りにつながった実例です。", url: nvd("CVE-2023-7028"), relation: "same-class" }],
  },
  jwt: {
    remediation: {
      objective: "アルゴリズムと鍵をサーバー側で固定し、必須claimを検証する",
      checklist: ["algを入力から選ばない", "kid/jkuを信頼済み鍵ストアに限定する", "iss・aud・expを検証する"],
      reviewNote: "署名があるだけでは不十分です。どの鍵と方式で、誰向けに発行されたかまで固定します。",
    },
    cves: [{ id: "CVE-2015-9235", title: "node-jsonwebtoken algorithm confusion", summary: "公開鍵をHMAC秘密鍵として扱わせ、攻撃者がJWT署名を偽造できたアルゴリズム混同の実例です。", url: nvd("CVE-2015-9235"), relation: "direct" }],
  },
  ssrf: {
    remediation: {
      objective: "名前解決後の接続先を検証し、許可した宛先へだけ接続する",
      checklist: ["schemeとportを許可リスト化する", "全ての解決IPを検証する", "リダイレクトごとに再検証する"],
      reviewNote: "URL文字列のホスト名だけを見ると、別表記・DNS・リダイレクトで内部IPへ到達できます。",
    },
    cves: [{ id: "CVE-2021-26855", title: "Microsoft Exchange ProxyLogon SSRF", summary: "外部からExchange内部のバックエンドへ任意リクエストを到達させたSSRFの実例です。", url: nvd("CVE-2021-26855"), relation: "same-class" }],
  },
  upload: {
    remediation: {
      objective: "内容を完全に解析・再生成し、実行不能な別オリジンへ保存する",
      checklist: ["ファイル名とContent-Typeを信用しない", "サーバー生成名を使う", "実行権限のない配信先へ隔離する"],
      reviewNote: "拡張子の許可リストだけでは多重拡張子、設定ファイル、ポリグロットを防げません。",
    },
    cves: [{ id: "CVE-2023-50164", title: "Apache Struts file upload path traversal", summary: "アップロード時のファイル名処理を悪用して任意位置へ配置し、コード実行につながり得た実例です。", url: nvd("CVE-2023-50164"), relation: "same-class" }],
  },
  crypto: {
    remediation: {
      objective: "標準の認証付き暗号を、秘密管理とnonce管理を含めて正しく使う",
      checklist: ["独自暗号や単なるエンコードを使わない", "AEADを利用する", "鍵をコードやクライアントへ置かない"],
      reviewNote: "アルゴリズム名だけでなく、鍵・nonce・署名対象・エラー処理を含む運用全体が安全性を決めます。",
    },
    cves: [{ id: "CVE-2017-15361", title: "ROCA weak RSA key generation", summary: "暗号ライブラリの鍵生成方式の弱さからRSA秘密鍵を推定可能にした、暗号実装失敗の実例です。", url: nvd("CVE-2017-15361"), relation: "same-class" }],
  },
  misconf: {
    remediation: {
      objective: "本番ビルドからデバッグ入口・秘密ファイル・管理APIを除去する",
      checklist: ["環境別の公開面を自動検査する", "deny by defaultにする", "秘密をWebルート外と秘密管理基盤に置く"],
      reviewNote: "個別URLを塞ぐ方式では、別表記や新しい管理エンドポイントが再び公開されます。",
    },
    cves: [{ id: "CVE-2021-3129", title: "Laravel Ignition debug mode RCE", summary: "本番で有効なデバッグ機能を足掛かりにコード実行へ至った、設定ミスと危険な機能露出の実例です。", url: nvd("CVE-2021-3129"), relation: "same-class" }],
  },
  deps: {
    remediation: {
      objective: "脆弱な依存関係と旧実装経路を資産一覧から継続的に排除する",
      checklist: ["SBOMと脆弱性スキャンをCIに入れる", "到達可能性を確認して更新する", "旧エンジンや互換経路も削除する"],
      reviewNote: "入口だけ更新しても、互換用の旧ライブラリが選択可能なら脆弱性は残ります。",
    },
    cves: [{ id: "CVE-2021-44228", title: "Apache Log4j Log4Shell", summary: "広く組み込まれた依存コンポーネントの危険な機能が遠隔コード実行につながった代表例です。", url: nvd("CVE-2021-44228"), relation: "same-class" }],
  },
  integrity: {
    remediation: {
      objective: "信頼済み秘密鍵による署名で、意味を持つ全フィールドを検証する",
      checklist: ["公開鍵を固定・ローテーション管理する", "正規化した全データを署名対象にする", "検証前のデータを利用しない"],
      reviewNote: "ハッシュだけ、配布物と同じ場所のHMAC鍵、一部フィールドだけの署名では改ざんを防げません。",
    },
    cves: [{ id: "CVE-2022-21449", title: "Java ECDSA Psychic Signatures", summary: "不正なECDSA署名を有効と判定し、署名で守られたデータの完全性を破れた検証実装の実例です。", url: nvd("CVE-2022-21449"), relation: "same-class" }],
  },
  logging: {
    remediation: {
      objective: "構造化・改ざん耐性・完全性のある監査イベントを、認可結果とともに記録する",
      checklist: ["制御文字を無害化する", "固定schemaで構造化する", "全ての重要操作と主体・結果を記録する"],
      reviewNote: "文字列連結ログは改行や制御文字で偽装できます。記録漏れも検知不能という同じ結果を招きます。",
    },
    cves: [{ id: "CVE-2021-42574", title: "Trojan Source bidirectional controls", summary: "Unicode双方向制御文字で表示上の意味を偽装する実例で、ログ表示の制御文字対策にも通じます。", url: nvd("CVE-2021-42574"), relation: "same-class" }],
  },
};
