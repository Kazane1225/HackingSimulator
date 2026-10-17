import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { ssrfRealLab } from "./labs/ssrf.js";
import type { LabInput, RealLab } from "./labs/runner.js";

type Exploits = Record<1 | 2 | 3 | 4, LabInput>;

/** Same checks as scripts/test-labs.ts (and server/src/labs.test.ts), but against the real engine. */
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

levelDesign(
  ssrfRealLab,
  {
    1: { url: "http://localhost/admin" },
    2: { url: "http://127.0.0.1/admin" },
    3: { url: "http://127.0.0.1.example.com/admin" },
    4: { url: "https://images.example.com/redirect?to=http://169.254.169.254/latest/meta-data" },
  },
  { url: "https://images.example.com/banner.png" },
);

describe("ssrf (real engine behaviour)", () => {
  it("the real URL parser normalizes a decimal IPv4 host (127.0.0.1 = 2130706433)", async () => {
    const r = await ssrfRealLab.run(1, { url: "http://2130706433/admin" });
    assert.equal(r.solved, true);
    assert.match(r.output.join("\n"), /access-key=/);
  });

  it("the decimal-notation bypass also works through the Lv4 redirect", async () => {
    const r = await ssrfRealLab.run(4, {
      url: "https://images.example.com/redirect?to=http://2852039166/latest/meta-data",
    });
    assert.equal(r.solved, true);
  });

  it("the real URL parser normalizes the IPv6 loopback literal", async () => {
    const r = await ssrfRealLab.run(1, { url: "http://[::1]/admin" });
    assert.equal(r.solved, true);
  });

  it("an unregistered host fails closed with a real resolver-style error", async () => {
    const r = await ssrfRealLab.run(1, { url: "http://evil.invalid/x" });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /ENOTFOUND/);
  });

  it("Lv5 performs a genuine successful fetch for an allowlisted public host", async () => {
    const r = await ssrfRealLab.run(5, { url: "https://images.example.com/banner.png" });
    assert.equal(r.solved, false);
    assert.equal(r.benign, true);
    assert.match(r.output.join("\n"), /\[200 OK\]/);
  });

  it("Lv5 re-validates every redirect hop, not just the first", async () => {
    const r = await ssrfRealLab.run(5, {
      url: "https://images.example.com/redirect?to=http://169.254.169.254/latest/meta-data",
    });
    assert.equal(r.solved, false);
  });

  it("rejects a non-http(s) scheme", async () => {
    const r = await ssrfRealLab.run(1, { url: "file:///etc/passwd" });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /スキーム/);
  });
});
