import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { idorRealLab } from "./labs/idor.js";
import type { LabInput, RealLab } from "./labs/runner.js";

type Exploits = Record<1 | 2 | 3 | 4, LabInput>;

const BOB_ORDER = "ORD-B0B-42";

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
  idorRealLab,
  {
    1: { endpoint: "/api/orders", orderId: "1002", owner: "alice", role: "user" },
    2: { endpoint: "/api/orders", orderId: BOB_ORDER, owner: "bob", role: "user" },
    3: { endpoint: "/api/export", orderId: BOB_ORDER, owner: "alice", role: "user" },
    // Identical to the simulated exploit: an empty query means the dev tab's
    // default `order(id: <orderId>)` resolver call.
    4: { endpoint: "/graphql", orderId: BOB_ORDER, owner: "alice", role: "user" },
  },
  { endpoint: "/api/orders", orderId: "1001", owner: "alice", role: "user", query: "" },
);

describe("idor (real engine behaviour)", () => {
  const explicitQuery = { endpoint: "/graphql", owner: "alice", role: "user", query: `{ order(id: "${BOB_ORDER}") { id item price } }` };

  it("an explicit GraphQL order(id:) query solves Lv4 through the real parser", async () => {
    assert.equal((await idorRealLab.run(4, explicitQuery)).solved, true);
  });

  it("an explicit query's id wins over a differing orderId", async () => {
    const r = await idorRealLab.run(4, { ...explicitQuery, orderId: "1001" });
    assert.equal(r.solved, true);
  });

  it("Lv3 and Lv5 do not fall for the explicit GraphQL query", async () => {
    assert.equal((await idorRealLab.run(3, explicitQuery)).solved, false);
    assert.equal((await idorRealLab.run(5, explicitQuery)).solved, false);
  });

  it("an empty GraphQL query without orderId is unsupported, not a leak", async () => {
    const r = await idorRealLab.run(4, { endpoint: "/graphql", query: "" });
    assert.equal(r.solved, false);
  });

  it("a valid query with no order selection falls back to the default resolver", async () => {
    const r = await idorRealLab.run(4, { endpoint: "/graphql", orderId: BOB_ORDER, query: "{ me { id } }" });
    assert.equal(r.solved, true);
  });

  it("reports a real GraphQL syntax error for a malformed query", async () => {
    const r = await idorRealLab.run(4, { endpoint: "/graphql", query: "{ order(id: ) }" });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /GraphQL 構文エラー/);
  });

  it("introspection reveals the schema without leaking data", async () => {
    const r = await idorRealLab.run(4, { endpoint: "/graphql", query: "{ __schema { types { name } } }" });
    assert.equal(r.solved, false);
    assert.equal(r.progress, true);
    assert.match(r.output.join("\n"), /type Order/);
  });

  it("formats the real SQLite-backed price for Bob's order", async () => {
    const r = await idorRealLab.run(3, { endpoint: "/api/export", orderId: BOB_ORDER, owner: "alice", role: "user" });
    assert.match(r.output.join("\n"), /¥89,800/);
  });

  it("the legacy sequential id no longer resolves once ids are hardened (Lv2+)", async () => {
    const r = await idorRealLab.run(2, { endpoint: "/api/orders", orderId: "1002", owner: "bob", role: "user" });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /403 FORBIDDEN/);
  });

  it("Alice's own order leaks the related order id from Lv3 onward", async () => {
    const r = await idorRealLab.run(3, { endpoint: "/api/orders", orderId: "1001", owner: "alice", role: "user" });
    assert.equal(r.solved, false);
    assert.equal(r.progress, true);
    assert.ok(r.loot?.some((l) => l.id === "idor-related" && l.value === BOB_ORDER));
  });

  it("an unknown order id is a clean miss, not a crash", async () => {
    const r = await idorRealLab.run(5, { endpoint: "/api/orders", orderId: "does-not-exist", owner: "alice", role: "user" });
    assert.equal(r.solved, false);
  });

  it("Lv5's GraphQL resolver authorizes by the real session subject, not the query", async () => {
    const r = await idorRealLab.run(5, {
      endpoint: "/graphql",
      query: `{ order(id: "${BOB_ORDER}") { id item price } }`,
    });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /403 FORBIDDEN/);
  });
});
