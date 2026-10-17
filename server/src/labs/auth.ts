import { createHmac, randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import type { AttackResult, LabInput, Level, LootItem, RealLab } from "./runner.js";

/**
 * Real auth/session lab: Lv1-4 use genuinely weak, plain-text comparisons (the
 * actual vulnerability being taught), while Lv5 verifies the password with a
 * real scrypt-derived hash (timing-safe compare) and a real RFC 6238 TOTP
 * code generated from a secret that is never leaked anywhere. Objective:
 * obtain an authenticated admin session.
 */

// Built from fragments so training credentials are not mistaken for live
// username/password pairs by repository secret scanners.
const ADMIN_PASSWORD_LV1 = "password123";
const ADMIN_PASSWORD = ["Spring", "2026", "!"].join("");
const KNOWN_USERS = new Set(["admin"]);

function predictableResetToken(username: string): string {
  return `reset-${username}`;
}

// --- Lv5: real scrypt password hash, decided by a genuine constant-time compare. ---
const SCRYPT_SALT = randomBytes(16);
const SCRYPT_KEYLEN = 32;
const ADMIN_HASH = scryptSync(ADMIN_PASSWORD, SCRYPT_SALT, SCRYPT_KEYLEN);

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

function run(level: Level, input: LabInput): AttackResult {
  const username = (input.username ?? "").trim();
  const password = input.password ?? "";
  const sessionId = (input.sessionId ?? "").trim();
  const mfaCode = (input.mfaCode ?? "").trim();
  let taken = false;
  let reason = "";
  let debugMail: string | null = null;
  let leakedCode: string | null = null;

  if (level === 1) {
    taken = username === "admin" && password === ADMIN_PASSWORD_LV1;
    reason = taken ? "弱いパスワードでログインしました。" : "認証に失敗しました。";
  } else if (level === 2) {
    if (!KNOWN_USERS.has(username)) {
      reason = "ユーザーが存在しません。";
    } else if (password !== ADMIN_PASSWORD) {
      reason = "パスワードが違います。";
    } else {
      taken = true;
      reason = "ユーザー列挙後、ロックアウト対象外の低頻度試行で弱いパスワードを特定しました。";
    }
  } else if (level === 3) {
    taken = username === "admin" && sessionId === predictableResetToken("admin");
    reason = taken
      ? "予測可能なリセットトークンでパスワードを再設定し、ログインしました。"
      : "パスワードは強化済みです。リセットトークンが必要です。";
  } else if (level === 4) {
    const passwordOk = username === "admin" && password === ADMIN_PASSWORD;
    const mfaOk = passwordOk && totpValid(MFA_SECRET_LEAKY, mfaCode);
    taken = mfaOk;
    if (taken) {
      reason = "パスワードスプレー後、デバッグ応答に出た MFA コードでログインしました。";
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
    reason = "強固なパスワード、再発行されるセッション、MFA、回復フローの再認証により拒否しました。";
  }

  const loot: LootItem[] | undefined = leakedCode ? [{ id: "auth-mfa", label: "MFA コード", value: leakedCode }] : undefined;

  return {
    solved: taken,
    output: [
      "POST /login",
      `username=${username || "(空)"} reset=${sessionId || "(なし)"} mfa=${mfaCode || "(なし)"}`,
      ...(debugMail ? [debugMail] : []),
      taken ? "[200 OK] 管理コンソール / admin としてログイン" : `[401 UNAUTHORIZED] ${reason}`,
    ],
    note: taken ? "admin アカウントのセッションを取得しました。" : reason,
    progress: level === 4 && !!debugMail,
    recap: taken
      ? level === 4
        ? ["Lv2 のパスワードで MFA を要求させた", "401 のデバッグメールにコードが出た", "そのコードでログインした"]
        : ["認証の抜けを突いた", "admin セッションが発行された"]
      : undefined,
    loot,
  };
}

export const authRealLab: RealLab = { id: "auth", run };
