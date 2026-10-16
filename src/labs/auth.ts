import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";

function run(level: Level, input: LabInput): AttackResult {
  const username = (input.username ?? "").trim();
  const password = input.password ?? "";
  const sessionId = (input.sessionId ?? "").trim();
  const mfaCode = (input.mfaCode ?? "").trim();
  let taken = false;
  let reason = "";

  if (level === 1) {
    taken = username === "admin" && password === "password123";
    reason = taken ? "弱いパスワードでログインしました。" : "認証に失敗しました。";
  } else if (level === 2) {
    taken = username === "admin" && password === "Spring2026!";
    reason = taken
      ? "ユーザー列挙後、ロックアウト対象外の低頻度試行で弱いパスワードを特定しました。"
      : username === "admin" ? "パスワードが違います。" : "ユーザーが存在しません。";
  } else if (level === 3) {
    taken = sessionId === "fixed-admin-session";
    reason = taken
      ? "ログイン後もセッション ID が再発行されず、固定したセッションを奪取しました。"
      : "認証情報は無効です。";
  } else if (level === 4) {
    taken = username === "admin" && password === "correct-horse-battery" && mfaCode === "recovery";
    reason = taken
      ? "回復フローが MFA を迂回し、パスワードだけでログインしました。"
      : "MFA を含む認証に失敗しました。";
  } else {
    reason = "強固なパスワード、再発行されるセッション、MFA、回復フローの再認証により拒否しました。";
  }

  return {
    solved: taken,
    output: [
      "POST /login",
      `username=${username || "(空)"} session=${sessionId || "(新規)"} mfa=${mfaCode || "(なし)"}`,
      taken ? "[200 OK] 管理コンソール / admin としてログイン" : `[401 UNAUTHORIZED] ${reason}`,
    ],
    note: taken ? "admin アカウントのセッションを取得しました。" : reason,
  };
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "試行回数制限がなく、よく使われる弱いパスワードを許可する。",
    hints: [
      "管理者がありがちなパスワードを使っていないでしょうか？",
      "回数制限がないため、辞書攻撃をシミュレートできます。",
      "`admin` / `password123` を試します。",
    ],
    solution: "ユーザー名 `admin`、パスワード `password123` でログインします。",
    code: `if (await verifyPassword(body.password, user.hash)) createSession(user);
// パスワード強度・レート制限なし`,
  },
  2: {
    defense: "IP 単位のレート制限だけを追加。エラー内容からユーザーを列挙できる。",
    hints: [
      "失敗メッセージが、存在するユーザーと存在しないユーザーで異なります。",
      "IP 単位の制限は分散・低頻度の試行を止められません。",
      "存在を確認した admin に、季節＋年のパスワード `Spring2026!` を試します。",
    ],
    solution: "`admin` / `Spring2026!`。列挙と低頻度パスワードスプレーで突破します。",
    code: `rateLimit(req.ip);
if (!user) return "ユーザーが存在しません";
if (!valid) return "パスワードが違います";`,
  },
  3: {
    defense: "エラーを統一しパスワードを強化したが、ログイン時にセッション ID を更新しない。",
    hints: [
      "パスワード以外に、ログイン状態を表す値を観察します。",
      "攻撃者が事前に決めたセッション ID がログイン後も同じならどうなりますか？",
      "`sessionId=fixed-admin-session` を送ってセッション固定を再現します。",
    ],
    solution: "セッション ID を `fixed-admin-session` に固定します。ログイン後の ID 再発行漏れにより奪取できます。",
    code: `const session = sessions.get(req.cookie.session) ?? createSession();
session.userId = user.id; // ID を rotate していない`,
  },
  4: {
    defense: "ログインには MFA を要求するが、アカウント回復フローが MFA を迂回する。",
    hints: [
      "強い認証も、別のログイン経路が弱ければ意味がありません。",
      "MFA コード欄は回復用の特別な値を受け付けています。",
      "`admin` / `correct-horse-battery` と MFA に `recovery` を送ります。",
    ],
    solution: "MFA コードに `recovery` を指定し、回復フローから MFA を迂回します。",
    code: `if (passwordOk && (totpOk || body.mfa === "recovery")) login();
// 回復処理で本人確認をしていない`,
  },
  5: {
    defense: "レート制限・安全なパスワード保存・セッション再発行・MFA・回復時の再認証を組み合わせる。",
    hints: [
      "認証は入口だけでなく、セッションと回復フローを含む一連の設計です。",
      "複数の防御をサーバー側で実施しているため、このレベルは突破できません。",
    ],
    solution: "突破不可能です。アカウント単位の制限と監視、MFA、セッションローテーション、安全な回復処理が適用されています。",
    code: `await limiter.check(user.id, req.ip);
await verifyArgon2id(password, user.hash);
const session = await rotateSession(oldSession);
await requireMfaOrRecoveryReauthentication(user);`,
  },
};

export const authLab: Lab = {
  meta: {
    id: "auth",
    title: "認証・セッション管理 — アカウント奪取",
    shortTitle: "認証 / Session",
    category: "認証",
    objective: "認証やセッション管理の不備を突き、admin のログイン状態を取得する。",
    summary: "弱いパスワード、ユーザー列挙、セッション固定、MFA 回復フローを検証する。",
    standards: {
      owasp: {
        code: "A07:2021",
        name: "Identification and Authentication Failures",
        url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
      },
      cwe: [
        { id: 307, name: "Improper Restriction of Excessive Authentication Attempts" },
        { id: 384, name: "Session Fixation" },
      ],
    },
    references: [
      { title: "OWASP Authentication Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html" },
      { title: "OWASP Session Management Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html" },
    ],
  },
  fields: [
    { name: "username", label: "ユーザー名", default: "guest", mono: true },
    { name: "password", label: "パスワード", default: "guest", mono: true },
    { name: "sessionId", label: "session ID", default: "", mono: true },
    { name: "mfaCode", label: "MFA コード", default: "", mono: true },
  ],
  explanation: `認証の安全性はパスワード照合だけでは決まりません。試行回数制限、ユーザー列挙を防ぐ統一エラー、強いパスワード保存、ログイン時のセッション ID 再発行、MFA、アカウント回復までが攻撃対象です。

レート制限は IP だけでなくアカウントも軸にし、段階的な遅延や監視を組み合わせます。セッション ID はログイン・権限変更時に必ず再発行し、Cookie に HttpOnly・Secure・SameSite を設定します。MFA の回復手続きは通常の MFA より弱い抜け道にしてはいけません。`,
  levels,
  run,
  exploits: {
    1: { username: "admin", password: "password123", sessionId: "", mfaCode: "" },
    2: { username: "admin", password: "Spring2026!", sessionId: "", mfaCode: "" },
    3: { username: "guest", password: "guest", sessionId: "fixed-admin-session", mfaCode: "" },
    4: { username: "admin", password: "correct-horse-battery", sessionId: "", mfaCode: "recovery" },
  },
};
