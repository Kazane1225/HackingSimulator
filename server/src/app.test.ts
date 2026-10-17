import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";
import { createApp, registerLab } from "./app.js";

describe("hacklab-server", () => {
  const server = createApp();
  let base = "";

  before(async () => {
    registerLab("/example", (_req, res) => {
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("example lab");
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it("reports health", async () => {
    const res = await fetch(`${base}/healthz`);
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { status: "ok" });
  });

  it("lists registered labs", async () => {
    const res = await fetch(`${base}/info`);
    const body = (await res.json()) as { name: string; labs: string[] };
    assert.equal(body.name, "hacklab-server");
    assert.deepEqual(body.labs, ["/example"]);
  });

  it("dispatches to a registered lab by prefix", async () => {
    const res = await fetch(`${base}/example/anything`);
    assert.equal(res.status, 200);
    assert.equal(await res.text(), "example lab");
  });

  it("returns 404 for unknown routes", async () => {
    const res = await fetch(`${base}/nope`);
    assert.equal(res.status, 404);
  });
});
