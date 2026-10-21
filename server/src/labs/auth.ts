import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import type { AttackResult, LabInput, Level, LootItem, RealLab } from "./runner.js";

/**
 * Real auth/session lab.
 * Lv1 accepts the last entry of the leaked wordlist and records no failures.
 * Lv2 locks an IP after 5 failures, but takes that IP from X-Forwarded-For.
 * The Lv2 password sits later in the same list, so one address locks first.
 * Lv3 is a predictable reset token. Lv4 leaks a real TOTP after that password.
 * Lv5 verifies a different password with scrypt and a never-leaked TOTP secret.
 *
 * PASSWORD_WORDLIST must stay aligned with src/labs/auth.ts.
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
export const LV5_PASSWORD = ["Spring", "2026", "!"].join("");
export const LOGIN_LOCK_AFTER = 5;
export const LOCKED_MARK = "[429 LOCKED]";
const LOCK_NOTE = "この IP からの試行はロックされています。";

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

// --- Lv5: real scrypt password hash, decided by a genuine constant-time compare. ---
const SCRYPT_SALT = randomBytes(16);
const SCRYPT_KEYLEN = 32;
const ADMIN_HASH = scryptSync(LV5_PASSWORD, SCRYPT_SALT, SCRYPT_KEYLEN);

function verifyPasswordScrypt(password: string): boolean {
  if (password.length === 0) return false;
  const candidate = scryptSync(password, SCRYPT_SALT, SCRYPT_KEYLEN);
  return candidate.length === ADMIN_HASH.length && timingSafeEqual(candidate, ADMIN_HASH);
}

// --- Real RFC 6238 TOTP. Lv4 uses a secret that gets leaked in a debug
// header (the actual flaw); Lv5 uses a *different*, never-leaked secret
// (secrets get rotated as part of a real remediation), so the Lv4 leak
// cannot be replayed against Lv5. ---
const TOTP_STEP_SECONDS = 120;
const TOTP_WINDOW = 1;
const MFA_SECRET_LEAKY = randomBytes(20);
const MFA_SECRET_SECURE = randomBytes(20);

function hotp(secret: Buffer, counter: number): string {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac("sha1", secret).update(buf).digest();
  const offset = digest[digest.length - 1] & 0xf;
  const code =
    (((digest[offset] & 0x7f) << 24) |
      ((digest[offset + 1] & 0xff) << 16) |
      ((digest[offset + 2] & 0xff) << 8) |
      (digest[offset + 3] & 0xff)) %
    1_000_000;
  return code.toString().padStart(6, "0");
}

function totpNow(secret: Buffer): string {
  return hotp(secret, Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS));
}

function totpValid(secret: Buffer, code: string): boolean {
  if (!/^\d{6}$/.test(code)) return false;
  const counter = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
  for (let w = -TOTP_WINDOW; w <= TOTP_WINDOW; w++) {
    if (hotp(secret, counter + w) === code) return true;
  }
  return false;
}

function predictableResetToken(username: string): string {
  return `reset-${username}`;
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
  let leakedCode: string | null = null;

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
    taken = username === "admin" && sessionId === predictableResetToken("admin");
    reason = taken
      ? "予測可能なリセットトークンでパスワードを再設定し、ログインしました。"
      : "パスワードは強化済みです。リセットトークンが必要です。";
  } else if (level === 4) {
    const passwordOk = username === "admin" && password === LV2_PASSWORD;
    const mfaOk = passwordOk && totpValid(MFA_SECRET_LEAKY, mfaCode);
    taken = mfaOk;
    if (taken) {
      reason = "Lv2 で当たったパスワードのあと、デバッグ応答に出た MFA コードでログインしました。";
    } else if (passwordOk) {
      leakedCode = totpNow(MFA_SECRET_LEAKY);
      reason = "パスワードは正しいですが MFA が必要です。";
      debugMail = `X-Debug-Mail: Your MFA code is ${leakedCode}`;
    } else {
      reason = "MFA を含む認証に失敗しました。";
    }
  } else {
    const passwordOk = username === "admin" && verifyPasswordScrypt(password);
    taken = passwordOk && totpValid(MFA_SECRET_SECURE, mfaCode);
    reason = "強固なパスワード、サーバが観測した接続元での制限、MFA、回復フローの再認証により拒否しました。";
  }

  const statusLine = locked
    ? `${LOCKED_MARK} ${LOCK_NOTE}`
    : taken
      ? "[200 OK] 管理コンソール / admin としてログイン"
      : `[401 UNAUTHORIZED] ${reason}`;

  const loot: LootItem[] | undefined = leakedCode
    ? [{ id: "auth-mfa", label: "MFA コード", value: leakedCode }]
    : taken && (level === 1 || level === 2)
      ? [{ id: `auth-password-lv${level}`, label: `Lv${level} のパスワード`, value: password }]
      : undefined;

  return {
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
    recap: taken
      ? level === 4
        ? ["Lv2 で当たったパスワードで MFA を要求させた", "401 のデバッグメールにコードが出た", "そのコードでログインした"]
        : level === 2
          ? ["この IP の失敗回数がロック未満だった", "流出一覧のパスワードが一致した", "admin セッションが発行された"]
          : level === 1
            ? ["流出一覧のパスワードが一致した", "失敗回数は記録されていない", "admin セッションが発行された"]
            : ["認証の抜けを突いた", "admin セッションが発行された"]
      : undefined,
    loot,
  };
}

export const authRealLab: RealLab = { id: "auth", run };
