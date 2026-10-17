import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { pathtraversalRealLab } from "./labs/pathtraversal.js";

const exploits = {
  1: { name: "../../../etc/passwd" },
  2: { name: "....//....//....//etc/passwd" },
  3: { name: "../../../etc/passwd%00.txt" },
  4: { name: "/var/www/secret/flag.txt" },
} as const;

const benign = { name: "readme.txt" };

describe("path (real)", () => {
  for (const lv of [1, 2, 3, 4] as const) {
    it(`Lv${lv} is solved by its exploit`, async () => {
      assert.equal((await pathtraversalRealLab.run(lv, exploits[lv])).solved, true);
    });
    if (lv > 1) {
      const prev = (lv - 1) as 1 | 2 | 3;
      it(`Lv${lv} blocks the Lv${prev} exploit`, async () => {
        assert.equal((await pathtraversalRealLab.run(lv, exploits[prev])).solved, false);
      });
    }
    it(`Lv5 resists the Lv${lv} exploit`, async () => {
      assert.equal((await pathtraversalRealLab.run(5, exploits[lv])).solved, false);
    });
  }
  for (const lv of [1, 2, 3, 4, 5] as const) {
    it(`Lv${lv} benign input does not solve`, async () => {
      assert.equal((await pathtraversalRealLab.run(lv, benign)).solved, false);
    });
  }
});

describe("path (real engine behaviour)", () => {
  it("reads a real planted secret file and reports it as loot", async () => {
    const r = await pathtraversalRealLab.run(4, exploits[4]);
    assert.ok(r.loot?.some((l) => l.id === "path-flag" && l.value === "FLAG{p4th_tr4v3rs4l}"));
  });

  it("surfaces node:fs's own ENOENT error for a missing file", async () => {
    const r = await pathtraversalRealLab.run(1, { name: "does-not-exist.txt" });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /ENOENT/);
  });

  it("never escapes the fixture root even for unmapped absolute targets", async () => {
    // Nothing is planted at this virtual path; the jail maps it to a
    // non-existent real file instead of reading anything on the real host.
    const r = await pathtraversalRealLab.run(1, { name: "../../../../../../root/.ssh/id_rsa" });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /ENOENT/);
  });

  it("Lv4's path.resolve() discards the base for an absolute name (real Node behaviour)", async () => {
    const r = await pathtraversalRealLab.run(4, { name: "/var/www/secret/flag.txt" });
    assert.equal(r.solved, true);
    assert.match(r.assembled ?? "", /path\.resolve/);
  });

  it("Lv5 keeps an absolute escape attempt outside the base after resolve()", async () => {
    const r = await pathtraversalRealLab.run(5, { name: "/var/www/secret/flag.txt" });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /DENY/);
  });

  it("serves the real readme content for the benign default", async () => {
    const r = await pathtraversalRealLab.run(1, benign);
    assert.match(r.output.join("\n"), /公開ファイル置き場/);
  });
});
