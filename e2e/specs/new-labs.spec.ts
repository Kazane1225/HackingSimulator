import { expect, test } from "../fixtures/test";
import { STATUS } from "../data/labels";
import { NEW_LABS } from "../data/newLabs";

const encode = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

test.describe("new vulnerability labs — target app", () => {
  test("IDOR own order is a normal response", async ({ lab }) => {
    await lab.goto("idor");
    await lab.setIntercept(false);
    const app = await lab.openApp();
    await app.getByRole("button", { name: "表示" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.benign);
    await expect(app.getByRole("cell", { name: "USB-C ケーブル" })).toBeVisible();
    await expect(app.getByText(/Alice \/ 1001/)).toBeVisible();
  });

  test("IDOR Lv1 exposes another user's order", async ({ lab }) => {
    await lab.goto("idor");
    await lab.setIntercept(false);
    await lab.send("orderId", "1002");
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    const app = await lab.openApp();
    await expect(app.getByText(/Bob .* ORD-B0B-42/)).toBeVisible();
  });

  test("authentication Lv2 distinguishes missing users from bad passwords", async ({ lab }) => {
    await lab.goto("auth");
    await lab.selectLevel(2);
    await lab.setIntercept(false);
    const app = await lab.openApp();
    await app.getByLabel("ユーザー名").fill("nobody");
    await app.getByLabel("パスワード").fill("x");
    await app.getByRole("button", { name: "ログイン" }).click();
    await expect(app.getByText("ユーザーが存在しません。")).toBeVisible();

    await app.getByLabel("ユーザー名").fill("admin");
    await app.getByRole("button", { name: "ログイン" }).click();
    await expect(app.getByText("パスワードが違います。")).toBeVisible();
  });

  test("authentication Lv1 is solved by sending the leaked wordlist", async ({ lab }) => {
    await lab.goto("auth");
    await lab.setParam("username", "admin");
    const app = await lab.openApp();
    await expect(app.getByText("leak.txt")).toBeVisible();
    await lab.openPane("proxy");
    await lab.pane("proxy").getByRole("button", { name: "一覧を送る" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(lab.page.getByTestId("dict-log")).toContainText("password123");
    await expect(lab.page.getByTestId("dict-log")).toContainText("200");
    await expect(app.getByText("admin としてログイン中")).toBeVisible();
  });

  test("authentication Lv2 locks one address until X-Forwarded-For changes", async ({ lab }) => {
    await lab.goto("auth");
    await lab.selectLevel(2);
    await lab.setParam("username", "admin");
    await lab.pane("proxy").getByRole("button", { name: "一覧を送る" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.progress);
    await expect(lab.page.getByTestId("dict-log")).toContainText("429");
    await expect(lab.page.getByTestId("dict-log")).toContainText("残り");

    await lab.pane("proxy").getByRole("checkbox", { name: "試行ごとに X-Forwarded-For を変える" }).check();
    await lab.pane("proxy").getByRole("button", { name: "一覧を送る" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(lab.page.getByTestId("dict-log")).toContainText("letmein");
    await expect(lab.page.getByTestId("dict-log")).toContainText("10.0.0.");
  });

  test("JWT Lv1 accepts an unsigned admin token", async ({ lab }) => {
    await lab.goto("jwt");
    await lab.setIntercept(false);
    const token = `${encode({ alg: "none", typ: "JWT" })}.${encode({ sub: "attacker", role: "admin" })}.`;
    const app = await lab.openApp();
    await app.getByLabel("raw JWT", { exact: true }).fill(token);
    await app.getByRole("button", { name: "GET /admin" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(app.getByText(/attacker \(admin\)/)).toBeVisible();
  });

  test("JWT editor assembles header and payload into a token", async ({ lab }) => {
    await lab.goto("jwt");
    await lab.setIntercept(false);
    const app = await lab.openApp();
    await app.getByLabel("JWT header", { exact: true }).fill(JSON.stringify({ alg: "none", typ: "JWT" }, null, 2));
    await app.getByLabel("JWT payload", { exact: true }).fill(JSON.stringify({ sub: "attacker", role: "admin" }, null, 2));
    await app.getByLabel("JWT signature", { exact: true }).fill("");
    await app.getByRole("button", { name: "GET /admin" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
  });

  test("JWT Lv2 signs HS256 with the weak secret", async ({ lab }) => {
    await lab.goto("jwt");
    await lab.selectLevel(2);
    await lab.setIntercept(false);
    const app = await lab.openApp();
    await app.getByLabel("JWT header", { exact: true }).fill(JSON.stringify({ alg: "HS256", typ: "JWT" }, null, 2));
    await app.getByLabel("JWT payload", { exact: true }).fill(JSON.stringify({ sub: "attacker", role: "admin" }, null, 2));
    await app.getByLabel("HMAC secret", { exact: true }).fill("secret");
    await app.getByRole("button", { name: "HS256 で署名" }).click();
    await app.getByRole("button", { name: "GET /admin" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
  });

  test("authentication Lv4 leaks the MFA code after a valid password", async ({ lab }) => {
    await lab.goto("auth");
    await lab.selectLevel(4);
    await lab.setIntercept(false);
    const app = await lab.openApp();
    await app.getByLabel("ユーザー名").fill("admin");
    await app.getByLabel("パスワード").fill("letmein");
    await app.getByRole("button", { name: "ログイン" }).click();
    await expect(app.getByText("パスワードは正しいですが MFA が必要です。")).toBeVisible();
    await expect(app.getByText(/Your MFA code is 482016/)).toBeVisible();

    await app.getByLabel("MFA コード").fill("482016");
    await app.getByRole("button", { name: "ログイン" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(app.getByText("admin としてログイン中")).toBeVisible();
  });

  test("SSRF Lv1 reaches localhost", async ({ lab }) => {
    await lab.goto("ssrf");
    await lab.setIntercept(false);
    const app = await lab.openApp();
    await app.getByLabel("取得する URL").fill("http://localhost/admin");
    await app.getByRole("button", { name: "取得" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(app.getByText(/SIMULATED_SECRET/)).toBeVisible();
  });

  test("file upload Lv1 stores an executable script", async ({ lab }) => {
    await lab.goto("upload");
    await lab.setIntercept(false);
    const app = await lab.openApp();
    await app.getByLabel("ファイル名").fill("shell.php");
    await app.getByLabel("ファイル内容").fill("<?php system('id'); ?>");
    await app.getByRole("button", { name: "アップロード" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(app.getByText("危険なファイルが実行されました。")).toBeVisible();
  });
});

test.describe("new vulnerability labs — proxy exploits", () => {
  for (const { id, exploits } of NEW_LABS) {
    for (const level of [1, 2, 3, 4] as const) {
      test(`${id} Lv${level} reference exploit clears the level`, async ({ lab }) => {
        await lab.goto(id);
        await lab.selectLevel(level);
        await lab.sendAll(exploits[level]);
        await expect(lab.statusBadge).toHaveText(STATUS.success);
      });
    }

    test(`${id} Lv5 blocks the Lv4 exploit`, async ({ lab }) => {
      await lab.goto(id);
      await lab.selectLevel(5);
      await lab.sendAll(exploits[4]);
      await expect(lab.statusBadge).toHaveText(STATUS.blocked);
    });
  }
});

test.describe("new vulnerability labs — intercept", () => {
  test("IDOR: tampering with a held order id exposes Bob's order", async ({ lab }) => {
    await lab.goto("idor");
    const app = await lab.openApp();
    await app.getByRole("button", { name: "表示" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.held);

    await lab.send("orderId", "1002");

    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(app.getByText(/Bob .* ORD-B0B-42/)).toBeVisible();
  });
});
