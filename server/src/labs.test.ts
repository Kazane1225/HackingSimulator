import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { cmdiRealLab } from "./labs/cmdi.js";
import type { LabInput, RealLab } from "./labs/runner.js";
import { sqliRealLab } from "./labs/sqli.js";

type Exploits = Record<1 | 2 | 3 | 4, LabInput>;

/** Same checks as scripts/test-labs.ts, but against the real engines. */
function levelDesign(lab: RealLab, exploits: Exploits, benign: LabInput, skip?: string): void {
  describe(`${lab.id} (real)`, { skip }, () => {
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
  sqliRealLab,
  {
    1: { username: "admin'-- ", password: "x", id: "", role: "user" },
    2: { username: "admin' OR '1'='1", password: "x", id: "", role: "user" },
    3: { username: "admin", password: "wrong", id: "1 OR 1=1", role: "user" },
    4: { username: "admin", password: "wrong", id: "", role: "' UNION SELECT username, password FROM users-- " },
  },
  { username: "admin", password: "wrong", id: "", role: "user" },
);

describe("sqli (real engine behaviour)", () => {
  it("reports the database's own syntax error", async () => {
    const r = await sqliRealLab.run(1, { username: "admin'", password: "x" });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /SQL ERROR/);
  });

  it("rejects a UNION with the wrong column count", async () => {
    const r = await sqliRealLab.run(4, {
      username: "admin",
      password: "wrong",
      role: "' UNION SELECT username, password, id FROM users-- ",
    });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /SQL ERROR/);
  });

  it("treats a legitimate login as a normal response", async () => {
    const r = await sqliRealLab.run(1, { username: "alice", password: "sunshine" });
    assert.equal(r.solved, false);
    assert.equal(r.benign, true);
  });

  it("reports leaked passwords as loot at Lv4", async () => {
    const r = await sqliRealLab.run(4, {
      username: "admin",
      password: "wrong",
      role: "' UNION SELECT username, password FROM users-- ",
    });
    assert.ok(r.loot?.some((l) => l.id === "sqli-pass-admin" && l.value === "S3cr3t-Pa55!"));
  });
});

// The command lab needs a POSIX /bin/sh; Windows developers can run these in Docker.
levelDesign(
  cmdiRealLab,
  {
    1: { host: "8.8.8.8; cat flag.txt" },
    2: { host: "8.8.8.8 && cat flag.txt" },
    3: { host: "8.8.8.8 $(cat flag.txt)" },
    4: { host: "'; cat flag.txt; '" },
  },
  { host: "8.8.8.8" },
  process.platform === "win32" ? "requires /bin/sh" : undefined,
);

describe("cmdi (real shell behaviour)", { skip: process.platform === "win32" ? "requires /bin/sh" : undefined }, () => {
  it("runs the ping stand-in for a plain host", async () => {
    const r = await cmdiRealLab.run(1, { host: "8.8.8.8" });
    assert.match(r.output.join("\n"), /64 bytes from 8\.8\.8\.8/);
  });

  it("does not pass secrets through the environment", async () => {
    process.env.HACKLAB_SECRET = "should-not-leak";
    const r = await cmdiRealLab.run(1, { host: "8.8.8.8; env" });
    delete process.env.HACKLAB_SECRET;
    assert.doesNotMatch(r.output.join("\n"), /should-not-leak/);
  });

  it("runs valid hosts without a shell at Lv5", async () => {
    const r = await cmdiRealLab.run(5, { host: "example.com" });
    assert.match(r.output.join("\n"), /64 bytes from example\.com/);
  });

  it("rejects shell metacharacters at Lv5", async () => {
    const r = await cmdiRealLab.run(5, { host: "8.8.8.8; cat flag.txt" });
    assert.match(r.output.join("\n"), /reject/);
  });
});
