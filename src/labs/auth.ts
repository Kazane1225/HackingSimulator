import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

/**
 * Leaked password list used by Lv1 and Lv2. Lv1's password is the last entry
 * (the list runs to the end). Lv2's password sits after {@link LOGIN_LOCK_AFTER}
 * failures, so one IP locks before that entry is tried. Keep this list aligned
 * with server/src/labs/auth.ts.
 */
export const PASSWORD_WORDLIST = [
  "123456",
  "password",
  "123456789",
  "qwerty",
  "12345678",
  "abc123",
  "password1",
  "111111",
  "iloveyou",
  "admin",
  "letmein",
  "welcome",
  "monkey",
  "dragon",
  "master",
  "sunshine",
  "princess",
  "football",
  "shadow",
  "password123",
] as const;

export const LV1_PASSWORD = "password123";
export const LV2_PASSWORD = "letmein";
export const LOGIN_LOCK_AFTER = 5;
export const LOCKED_MARK = "[429 LOCKED]";
const LOCK_NOTE = "この IP からの試行はロックされています。";

export const DEBUG_MFA = "482016";

const KNOWN_USERS = new Set(["admin"]);
const failuresByIp = new Map<string, number>();

export function resetLoginAttempts(): void {
  failuresByIp.clear();
}

function clientIp(input: LabInput): string {
  const raw = (input.forwardedFor ?? "").split(",")[0]?.trim() ?? "";
  return raw || "direct";
}

function failureKey(ip: string, username: string): string {
  return `${ip}\n${username}`;
}

function lockedOut(username: string, ip: string): boolean {
  return (failuresByIp.get(failureKey(ip, username)) ?? 0) >= LOGIN_LOCK_AFTER;
}

function recordFailure(username: string, ip: string): void {
  const key = failureKey(ip, username);
  failuresByIp.set(key, (failuresByIp.get(key) ?? 0) + 1);
}

function run(level: Level, input: LabInput): AttackResult {
  const username = (input.username ?? "").trim();
  const password = input.password ?? "";
  const sessionId = (input.sessionId ?? "").trim();
  const mfaCode = (input.mfaCode ?? "").trim();
  const ip = clientIp(input);
  let taken = false;
  let locked = false;
  let reason = "";
  let debugMail: string | null = null;

  if (level === 1) {
    taken = username === "admin" && password === LV1_PASSWORD;
    reason = taken
      ? "流出一覧に含まれるパスワードでログインしました。失敗回数は記録していません。"
      : "認証に失敗しました。";
  } else if (level === 2) {
    if (lockedOut(username, ip)) {
      locked = true;
      reason = LOCK_NOTE;
    } else if (!KNOWN_USERS.has(username)) {
      recordFailure(username, ip);
      reason = "ユーザーが存在しません。";
    } else if (password !== LV2_PASSWORD) {
      recordFailure(username, ip);
      reason = "パスワードが違います。";
    } else {
      taken = true;
      reason = "この IP ではまだロック前で、流出一覧のパスワードが一致しました。";
    }
  } else if (level === 3) {
    taken = username === "admin" && sessionId === "reset-admin";
    reason = taken
      ? "予測可能なリセットトークンでパスワードを再設定し、ログインしました。"
      : "パスワードは強化済みです。リセットトークンが必要です。";
  } else if (level === 4) {
    const passwordOk = username === "admin" && password === LV2_PASSWORD;
    const mfaOk = mfaCode === DEBUG_MFA;
    taken = passwordOk && mfaOk;
    if (taken) {
      reason = "Lv2 で当たったパスワードのあと、デバッグ応答に出た MFA コードでログインしました。";
    } else if (passwordOk) {
      reason = "パスワードは正しいですが MFA が必要です。";
      debugMail = `X-Debug-Mail: Your MFA code is ${DEBUG_MFA}`;
    } else {
      reason = "MFA を含む認証に失敗しました。";
    }
  } else {
    reason = "強固なパスワード、サーバが観測した接続元での制限、MFA、回復フローの再認証により拒否しました。";
  }

  const statusLine = locked
    ? `${LOCKED_MARK} ${LOCK_NOTE}`
    : taken
      ? "[200 OK] 管理コンソール / admin としてログイン"
      : `[401 UNAUTHORIZED] ${reason}`;

  const passwordLoot =
    taken && (level === 1 || level === 2)
      ? [{ id: `auth-password-lv${level}`, label: `Lv${level} のパスワード`, value: password }]
      : undefined;

  return traced(
    {
      solved: taken,
      output: [
        "POST /login",
        `username=${username || "(空)"} reset=${sessionId || "(なし)"} mfa=${mfaCode || "(なし)"}`,
        ...(level === 2 ? [`X-Forwarded-For: ${ip}`] : []),
        ...(debugMail ? [debugMail] : []),
        statusLine,
      ],
      note: taken ? "admin アカウントのセッションを取得しました。" : reason,
      progress: level === 4 && !!debugMail,
    },
    `verify(user=${username || "?"}, password=…, mfa=${mfaCode || "(なし)"}, reset=${sessionId || "(なし)"})`,
    {
      recap: taken
        ? level === 4
          ? ["Lv2 で当たったパスワードで MFA を要求させた", "401 のデバッグメールにコードが出た", "そのコードでログインした"]
          : level === 2
            ? ["この IP の失敗回数がロック未満だった", "流出一覧のパスワードが一致した", "admin セッションが発行された"]
            : level === 1
              ? ["流出一覧のパスワードが一致した", "失敗回数は記録されていない", "admin セッションが発行された"]
              : ["認証の抜けを突いた", "admin セッションが発行された"]
        : undefined,
      loot: debugMail ? [{ id: "auth-mfa", label: "MFA コード", value: DEBUG_MFA }] : passwordLoot,
    },
  );
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "失敗回数を記録せず、流出一覧に載る弱いパスワードを許可する。",
    hints: [
      "ログイン画面に leak.txt という流出パスワードの一覧があります。",
      "このレベルは失敗回数を数えません。一覧は最後まで届きます。",
      "username を `admin` にして、Proxy の「一覧を送る」を押します。200 の行がパスワードです。",
    ],
    solution: "username を `admin` にして一覧を送る。最後の `password123` でログインできる。サーバは途中で止めない。",
    code: `// 失敗回数を記録しない
if (user.password === body.password) createSession(user);`,
  },
  2: {
    defense: "同一 IP で 5 回失敗するとロックする。ただしその IP を X-Forwarded-For から決める。",
    hints: [
      "同じ一覧を 1 つの IP から送ると、5 回失敗したあとロックされ、残りの候補は試されません。",
      "ソースではロックのキーになる IP を、リクエストの X-Forwarded-For から取っています。",
      "「試行ごとに X-Forwarded-For を変える」をオンにして、同じ一覧を送ります。",
    ],
    solution:
      "一覧の `letmein` は 5 回のロックより後ろにあります。試行ごとに X-Forwarded-For を変えて一覧を送ると、そのパスワードでログインできます。失敗文の差から、存在するユーザーも分かります。",
    code: `const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
if ((attempts[ip] ?? 0) >= 5) return locked();
if (!user) return "ユーザーが存在しません";
if (!valid) {
  attempts[ip]++;
  return "パスワードが違います";
}`,
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
      "リセットトークンは無効です。Lv2 の一覧で通ったパスワードは、このレベルのパスワード欄に使えます。",
      "パスワードが正しいときのエラー応答をよく見てください。",
      "デバッグヘッダ `X-Debug-Mail` に出た 6 桁を MFA コードへ入れます。",
    ],
    solution: `Lv2 で見つかったパスワード \`${LV2_PASSWORD}\` で MFA を要求させ、応答のコード \`${DEBUG_MFA}\` を送ります。`,
    code: `if (passwordOk && !totpOk) {
  res.set("X-Debug-Mail", "Your MFA code is " + user.debugOtp); // 本番に残っている
  return 401;
}`,
  },
  5: {
    defense: "接続元の制限、安全なパスワード保存、セッション再発行、MFA、回復時の再認証を組み合わせる。",
    hints: [
      "認証は入口だけでなく、セッションと回復フローを含む一連の設計です。",
      "複数の防御をサーバー側で実施しているため、このレベルは突破できません。",
    ],
    solution: "突破不可能です。アカウント単位の制限と監視、MFA、セッションローテーション、安全な回復処理が適用されています。接続元はクライアント申告のヘッダではありません。",
    code: `await limiter.check(user.id, req.socket.remoteAddress);
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
    summary: "回数制限のない辞書攻撃、X-Forwarded-For を信用したロック、予測可能なリセット、MFA コードのデバッグ漏洩を検証する。",
    standards: {
      owasp: {
        code: "A07:2021",
        name: "Identification and Authentication Failures",
        url: "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
      },
      cwe: [
        { id: 307, name: "Improper Restriction of Excessive Authentication Attempts" },
        { id: 348, name: "Use of Less Trusted Source" },
        { id: 209, name: "Generation of Error Message Containing Sensitive Information" },
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
  explanation: `認証の安全性はパスワード照合だけでは決まりません。流出したパスワード一覧を何回でも試せるログイン、ロックの相手をクライアント申告の IP にしている実装、予測可能なリセットトークン、エラー応答に残った MFA コードが攻撃対象です。

失敗回数はアカウントと、サーバが観測した接続元の両方で数えます。X-Forwarded-For はクライアントが自由に書けるので、ロックのキーにしてはいけません。リセットトークンはユーザー名から作らず十分な乱数にします。MFA コードをデバッグヘッダやメールプレビューに出してはいけません。`,
  levels,
  run,
  exploits: {
    1: { username: "admin", password: LV1_PASSWORD, sessionId: "", mfaCode: "" },
    2: { username: "admin", password: LV2_PASSWORD, sessionId: "", mfaCode: "" },
    3: { username: "admin", password: "x", sessionId: "reset-admin", mfaCode: "" },
    4: { username: "admin", password: LV2_PASSWORD, sessionId: "", mfaCode: DEBUG_MFA },
  },
};
