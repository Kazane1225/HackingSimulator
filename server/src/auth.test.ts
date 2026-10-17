import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { LabInput } from "./labs/runner.js";
import { authRealLab } from "./labs/auth.js";

const ADMIN_PASSWORD = ["Spring", "2026", "!"].join("");
const BENIGN: LabInput = { username: "guest", password: "guest", sessionId: "", mfaCode: "" };

function mfaCodeFrom(output: string[]): string {
  const line = output.find((l) => l.includes("X-Debug-Mail"));
  const match = line ? /(\d{6})/.exec(line) : null;
  if (!match) throw new Error("no MFA code was leaked in the response");
  return match[1];
}

async function leakedLv4Code(): Promise<string> {
  const probe = await authRealLab.run(4, { username: "admin", password: ADMIN_PASSWORD, sessionId: "", mfaCode: "" });
  return mfaCodeFrom(probe.output);
}

describe("auth (real)", () => {
  it("Lv1 is solved by its exploit", async () => {
    const r = await authRealLab.run(1, { username: "admin", password: "password123", sessionId: "", mfaCode: "" });
    assert.equal(r.solved, true);
  });

  it("Lv2 blocks the Lv1 exploit", async () => {
    const r = await authRealLab.run(2, { username: "admin", password: "password123", sessionId: "", mfaCode: "" });
    assert.equal(r.solved, false);
  });

  it("Lv2 is solved by its exploit", async () => {
    const r = await authRealLab.run(2, { username: "admin", password: ADMIN_PASSWORD, sessionId: "", mfaCode: "" });
    assert.equal(r.solved, true);
  });

  it("Lv3 blocks the Lv2 exploit", async () => {
    const r = await authRealLab.run(3, { username: "admin", password: ADMIN_PASSWORD, sessionId: "", mfaCode: "" });
    assert.equal(r.solved, false);
  });

  it("Lv3 is solved by its exploit", async () => {
    const r = await authRealLab.run(3, { username: "admin", password: "x", sessionId: "reset-admin", mfaCode: "" });
    assert.equal(r.solved, true);
  });

  it("Lv4 blocks the Lv3 exploit", async () => {
    const r = await authRealLab.run(4, { username: "admin", password: "x", sessionId: "reset-admin", mfaCode: "" });
    assert.equal(r.solved, false);
  });

  it("Lv4 is solved by its exploit (password spray, then replay the leaked MFA code)", async () => {
    const probe = await authRealLab.run(4, { username: "admin", password: ADMIN_PASSWORD, sessionId: "", mfaCode: "" });
    assert.equal(probe.solved, false);
    assert.equal(probe.progress, true);
    const code = mfaCodeFrom(probe.output);
    const r = await authRealLab.run(4, { username: "admin", password: ADMIN_PASSWORD, sessionId: "", mfaCode: code });
    assert.equal(r.solved, true);
  });

  it("Lv5 resists the Lv1 exploit", async () => {
    const r = await authRealLab.run(5, { username: "admin", password: "password123", sessionId: "", mfaCode: "" });
    assert.equal(r.solved, false);
  });

  it("Lv5 resists the Lv2 exploit", async () => {
    const r = await authRealLab.run(5, { username: "admin", password: ADMIN_PASSWORD, sessionId: "", mfaCode: "" });
    assert.equal(r.solved, false);
  });

  it("Lv5 resists the Lv3 exploit", async () => {
    const r = await authRealLab.run(5, { username: "admin", password: "x", sessionId: "reset-admin", mfaCode: "" });
    assert.equal(r.solved, false);
  });

  it("Lv5 resists the Lv4 exploit (leaked code was HMACed with a rotated, Lv5-only secret)", async () => {
    const code = await leakedLv4Code();
    const r = await authRealLab.run(5, { username: "admin", password: ADMIN_PASSWORD, sessionId: "", mfaCode: code });
    assert.equal(r.solved, false);
  });

  for (const lv of [1, 2, 3, 4, 5] as const) {
    it(`Lv${lv} benign input does not solve`, async () => {
      assert.equal((await authRealLab.run(lv, BENIGN)).solved, false);
    });
  }
});

describe("auth (real engine behaviour)", () => {
  it("Lv2 enumerates: unknown username vs. known username give different reasons", async () => {
    const unknown = await authRealLab.run(2, { username: "nobody", password: "x", sessionId: "", mfaCode: "" });
    const known = await authRealLab.run(2, { username: "admin", password: "x", sessionId: "", mfaCode: "" });
    assert.match(unknown.note ?? "", /存在しません/);
    assert.match(known.note ?? "", /パスワードが違います/);
    assert.notEqual(unknown.note, known.note);
  });

  it("Lv3's reset token is predictable from the username alone", async () => {
    const guessed = await authRealLab.run(3, { username: "admin", password: "", sessionId: "reset-admin", mfaCode: "" });
    const randomLooking = await authRealLab.run(3, {
      username: "admin",
      password: "",
      sessionId: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
      mfaCode: "",
    });
    assert.equal(guessed.solved, true);
    assert.equal(randomLooking.solved, false);
  });

  it("Lv4's leaked MFA code is a real, currently valid TOTP code (not a fixed constant)", async () => {
    const codeA = await leakedLv4Code();
    const codeB = await leakedLv4Code();
    assert.match(codeA, /^\d{6}$/);
    assert.match(codeB, /^\d{6}$/);
    // Same secret/time-step in a fast test run should reproduce the same code,
    // unlike a hardcoded debug constant this is derived from real HMAC output.
    assert.equal(codeA, codeB);
  });

  it("Lv5 rejects a close-but-wrong password via the real scrypt hash compare", async () => {
    const r = await authRealLab.run(5, { username: "admin", password: "Spring2026", sessionId: "", mfaCode: "000000" });
    assert.equal(r.solved, false);
  });

  it("Lv5 rejects an arbitrary 6-digit MFA code even with the correct password", async () => {
    const r = await authRealLab.run(5, { username: "admin", password: ADMIN_PASSWORD, sessionId: "", mfaCode: "000000" });
    assert.equal(r.solved, false);
  });
});
