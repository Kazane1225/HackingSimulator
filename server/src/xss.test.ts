import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { xssRealLab } from "./labs/xss.js";
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

levelDesign(
  xssRealLab,
  {
    1: { comment: "<script>alert(1)</script>" },
    2: { comment: "<img src=x onerror=alert(1)>" },
    3: { comment: '" onerror=alert(1) x="' },
    4: { comment: "</script><img src=x onerror=alert(1)>" },
  },
  { comment: "こんにちは！" },
);

describe("xss (real engine behaviour)", () => {
  it("Lv1 reflects the script tag completely unfiltered", async () => {
    const r = await xssRealLab.run(1, { comment: "<script>alert(1)</script>" });
    assert.match(r.renderHtml ?? "", /<script>alert\(1\)<\/script>/);
  });

  it("Lv2 strips the script tag but leaves the onerror attribute", async () => {
    const r = await xssRealLab.run(2, { comment: "<img src=x onerror=alert(1)>" });
    assert.doesNotMatch(r.renderHtml ?? "", /<script>/i);
    assert.match(r.renderHtml ?? "", /onerror=alert\(1\)/);
  });

  it("Lv5 HTML-encodes every special character - a real encoder, not a blocklist", async () => {
    const r = await xssRealLab.run(5, { comment: `<script>alert('x')</script>` });
    assert.equal(r.renderHtml, `<div class="guest-comment">&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;</div>`);
    assert.equal(r.solved, false);
  });

  it("runs injected script for real with a timeout guard (no hang on an infinite loop)", async () => {
    const start = Date.now();
    const r = await xssRealLab.run(1, { comment: "<script>while(true){}</script>" });
    assert.ok(Date.now() - start < 2000, "must not hang on attacker-controlled script");
    assert.equal(r.solved, false, "a loop that never calls alert() must not count as fired");
  });

  it("a quoted attribute value containing onerror-like text is not a vector (real attribute tokenizing)", async () => {
    // The whole "onerror=alert(1)" text lives *inside* the alt="..." value,
    // so a correct tokenizer must not treat it as a separate attribute.
    const r = await xssRealLab.run(3, { comment: "just text, not a breakout" });
    assert.equal(r.solved, false);
  });

  it("an unterminated JS string from early </script> closure does not itself execute", async () => {
    // At Lv4 the comment's "</script>" ends the real <script> element early;
    // the remaining `var comment = '` left inside is a genuine syntax error.
    const r = await xssRealLab.run(4, { comment: "</script><div>no vector here</div>" });
    assert.equal(r.solved, false);
  });
});
