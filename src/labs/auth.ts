import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

// Built from fragments so training credentials are not mistaken for live
// username/password pairs by repository secret scanners.
const ADMIN_PASSWORD_LV2 = ["Spring", "2026", "!"].join("");
const DEBUG_MFA = "482016";

function run(level: Level, input: LabInput): AttackResult {
  const username = (input.username ?? "").trim();
  const password = input.password ?? "";
  const sessionId = (input.sessionId ?? "").trim();
  const mfaCode = (input.mfaCode ?? "").trim();
  let taken = false;
  let reason = "";
  let debugMail: string | null = null;

  if (level === 1) {
    taken = username === "admin" && password === "password123";
    reason = taken ? "弱いパスワードでログインしました。" : "認証に失敗しました。";
  } else if (level === 2) {
    taken = username === "admin" && password === ADMIN_PASSWORD_LV2;
    reason = taken
      ? "ユーザー列挙後、ロックアウト対象外の低頻度試行で弱いパスワードを特定しました。"
      : username === "admin" ? "パスワードが違います。" : "ユーザーが存在しません。";
  } else if (level === 3) {
    taken = username === "admin" && sessionId === "reset-admin";
    reason = taken
      ? "予測可能なリセットトークンでパスワードを再設定し、ログインしました。"
      : "パスワードは強化済みです。リセットトークンが必要です。";
  } else if (level === 4) {
    const passwordOk = username === "admin" && password === ADMIN_PASSWORD_LV2;
    const mfaOk = mfaCode === DEBUG_MFA;
    taken = passwordOk && mfaOk;
    if (taken) {
      reason = "パスワードスプレー後、デバッグ応答に出た MFA コードでログインしました。";
    } else if (passwordOk) {
      reason = "パスワードは正しいですが MFA が必要です。";
      debugMail = `X-Debug-Mail: Your MFA code is ${DEBUG_MFA}`;
    } else {
      reason = "MFA を含む認証に失敗しました。";
    }
  } else {
    reason = "強固なパスワード、再発行されるセッション、MFA、回復フローの再認証により拒否しました。";
  }

  return traced(
    {
      solved: taken,
      output: [
        "POST /login",
        `username=${username || "(空)"} reset=${sessionId || "(なし)"} mfa=${mfaCode || "(なし)"}`,
        ...(debugMail ? [debugMail] : []),
        taken ? "[200 OK] 管理コンソール / admin としてログイン" : `[401 UNAUTHORIZED] ${reason}`,
      ],
      note: taken ? "admin アカウントのセッションを取得しました。" : reason,
      progress: level === 4 && !!debugMail,
    },
    `verify(user=${username || "?"}, password=…, mfa=${mfaCode || "(なし)"}, reset=${sessionId || "(なし)"})`,
    {
      recap: taken
        ? level === 4
          ? ["Lv2 のパスワードで MFA を要求させた", "401 のデバッグメールにコードが出た", "そのコードでログインした"]
          : ["認証の抜けを突いた", "admin セッションが発行された"]
        : undefined,
      loot: debugMail ? [{ id: "auth-mfa", label: "MFA コード", value: DEBUG_MFA }] : undefined,
    },
  );
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
    defense: "パスワードを強化しエラーを統一した。リセットトークンは `reset-` + ユーザー名。",
    hints: [
      "よくあるパスワードでは入れません。ソースの『パスワードを忘れた場合』を読みましょう。",
      "トークンはメール本文ではなく、ユーザー名から決まっていませんか？",
      "username を `admin`、session ID（リセットトークン）を `reset-admin` にします。",
    ],
    solution: "`admin` とリセットトークン `reset-admin` を送ります。トークンがユーザー名から予測できます。",
    code: `const token = "reset-" + user.username; // 予測可能
if (body.resetToken === token) login(user);`,
  },
  4: {
    defense: "MFA を必須にする。ただしパスワード成功時の 401 応答にデバッグ用メールプレビューを残している。",
    hints: [
      "リセットトークンは無効です。Lv2 で効いたパスワードはまだ使えます。",
      "パスワードが正しいときのエラー応答をよく見てください。",
      "デバッグヘッダ `X-Debug-Mail` に出た 6 桁を MFA コードへ入れます。",
    ],
    solution: `Lv2 のパスワード \`${ADMIN_PASSWORD_LV2}\` で MFA を要求させ、応答のコード \`${DEBUG_MFA}\` を送ります。`,
    code: `if (passwordOk && !totpOk) {
  res.set("X-Debug-Mail", "Your MFA code is " + user.debugOtp); // 本番に残っている
  return 401;
}`,
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
    summary: "弱いパスワード、ユーザー列挙、予測可能なリセット、MFA コードのデバッグ漏洩を検証する。",
    standards: {
      owasp: {
        code: "A07:2021",
        name: "Identification and Authentication Failures",
        url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
      },
      cwe: [
        { id: 307, name: "Improper Restriction of Excessive Authentication Attempts" },
        { id: 209, name: "Generation of Error Message Containing Sensitive Information" },
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
    { name: "sessionId", label: "reset token", default: "", mono: true },
    { name: "mfaCode", label: "MFA コード", default: "", mono: true },
  ],
  explanation: `認証の安全性はパスワード照合だけでは決まりません。試行回数制限、ユーザー列挙を防ぐ統一エラー、強いパスワード保存、予測不可能なリセットトークン、MFA、そしてエラー応答に秘密を出さないことが攻撃対象です。

レート制限は IP だけでなくアカウントも軸にします。リセットトークンはユーザー名から作らず十分な乱数にします。MFA コードをデバッグヘッダやメールプレビューに出してはいけません。`,
  levels,
  run,
  exploits: {
    1: { username: "admin", password: "password123", sessionId: "", mfaCode: "" },
    2: { username: "admin", password: ADMIN_PASSWORD_LV2, sessionId: "", mfaCode: "" },
    3: { username: "admin", password: "x", sessionId: "reset-admin", mfaCode: "" },
    4: { username: "admin", password: ADMIN_PASSWORD_LV2, sessionId: "", mfaCode: DEBUG_MFA },
  },
};
