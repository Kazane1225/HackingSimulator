import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { describe, it } from "node:test";
import { ATTACKER_JKU, buildJwtExploitTokens, getRsaPublicKeyPem, jwtRealLab } from "./labs/jwt.js";

function encodePart(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function signHmac(header: unknown, payload: unknown, secret: Buffer): string {
  const data = `${encodePart(header)}.${encodePart(payload)}`;
  const sig = createHmac("sha256", secret).update(data).digest().toString("base64url");
  return `${data}.${sig}`;
}

const tokens = buildJwtExploitTokens();
const exploits: Record<1 | 2 | 3 | 4, string> = {
  1: tokens.none,
  2: tokens.weakHmac,
  3: tokens.confusion,
  4: tokens.jku,
};

describe("jwt (real)", () => {
  for (const lv of [1, 2, 3, 4] as const) {
    it(`Lv${lv} is solved by its exploit`, async () => {
      assert.equal((await jwtRealLab.run(lv, { token: exploits[lv] })).solved, true);
    });
    if (lv > 1) {
      const prev = (lv - 1) as 1 | 2 | 3;
      it(`Lv${lv} blocks the Lv${prev} exploit`, async () => {
        assert.equal((await jwtRealLab.run(lv, { token: exploits[prev] })).solved, false);
      });
    }
    it(`Lv5 resists the Lv${lv} exploit`, async () => {
      assert.equal((await jwtRealLab.run(5, { token: exploits[lv] })).solved, false);
    });
  }

  it("benign default token does not solve any level", async () => {
    for (const lv of [1, 2, 3, 4, 5] as const) {
      assert.equal((await jwtRealLab.run(lv, { token: tokens.benign })).solved, false);
    }
  });
});

describe("jwt (real engine behaviour)", () => {
  it("rejects malformed tokens", async () => {
    const r = await jwtRealLab.run(1, { token: "not-a-jwt" });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /不正/);
  });

  it("verifies the benign token's real RS256 signature", async () => {
    const r = await jwtRealLab.run(1, { token: tokens.benign });
    assert.equal(r.benign, true);
  });

  it("rejects the benign token once its payload is tampered (real signature no longer matches)", async () => {
    const [head, , sig] = tokens.benign.split(".");
    const tamperedBody = encodePart({ sub: "alice", role: "admin" });
    const r = await jwtRealLab.run(1, { token: `${head}.${tamperedBody}.${sig}` });
    assert.equal(r.solved, false);
  });

  it("the algorithm-confusion key must be the real public key, not a guess", async () => {
    const guess = signHmac({ alg: "HS256", typ: "JWT" }, { sub: "attacker", role: "admin" }, Buffer.from("rsa-public-key-guess"));
    const r = await jwtRealLab.run(3, { token: guess });
    assert.equal(r.solved, false);
  });

  it("the real public key used as an HMAC secret does solve Lv3 (algorithm confusion)", async () => {
    const forged = signHmac(
      { alg: "HS256", typ: "JWT" },
      { sub: "attacker", role: "admin" },
      Buffer.from(getRsaPublicKeyPem(), "utf8"),
    );
    const r = await jwtRealLab.run(3, { token: forged });
    assert.equal(r.solved, true);
  });

  it("fetches the planted JWKS (the same ATTACKER_JKU/key the simulated lab uses) at Lv4", async () => {
    const r = await jwtRealLab.run(4, { token: tokens.jku });
    assert.equal(r.solved, true);
    assert.match(r.output.join("\n"), new RegExp(`JWKS ${ATTACKER_JKU.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    assert.ok(r.loot?.some((l) => l.id === "jwt-oct" && l.value === "evil-hmac-key"));
  });

  it("blocks a jku that isn't the planted attacker URL, even if otherwise well-formed", async () => {
    const [, body, sig] = tokens.jku.split(".");
    const header = encodePart({ alg: "HS256", typ: "JWT", jku: "https://not-planted.example/jwks.json", kid: "evil" });
    const r = await jwtRealLab.run(4, { token: `${header}.${body}.${sig}` });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /JWKS fetch failed/);
  });

  it("Lv3-5 expose the server's public key via a /.well-known-style line", async () => {
    const r = await jwtRealLab.run(3, { token: tokens.benign });
    assert.match(r.output.join("\n"), /jwks-public\.pem/);
    assert.match(r.output.join("\n"), /BEGIN PUBLIC KEY/);
  });

  it("Lv5 ignores jku entirely", async () => {
    const r = await jwtRealLab.run(5, { token: tokens.jku });
    assert.match(r.output.join("\n"), /無視されました/);
  });
});
