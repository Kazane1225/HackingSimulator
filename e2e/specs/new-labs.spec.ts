import { expect, test } from "../fixtures/test";
import { STATUS } from "../data/labels";
import { NEW_LABS } from "../data/newLabs";

const encode = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

test.describe("new vulnerability labs — target app", () => {
  test("IDOR own order is a normal response", async ({ page, lab }) => {
    await lab.goto("idor");
    await lab.setIntercept(false);
    await page.getByRole("button", { name: "表示" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.benign);
    await expect(lab.pane("target").getByRole("cell", { name: "USB-C ケーブル" })).toBeVisible();
    await expect(lab.pane("target").getByText(/Alice \/ 1001/)).toBeVisible();
  });

  test("IDOR Lv1 exposes another user's order", async ({ lab }) => {
    await lab.goto("idor");
    await lab.setIntercept(false);
    await lab.send("orderId", "1002");
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(lab.pane("target").getByText(/Bob .* ORD-B0B-42/)).toBeVisible();
  });

  test("authentication Lv2 distinguishes missing users from bad passwords", async ({ page, lab }) => {
    await lab.goto("auth");
    await lab.selectLevel(2);
    await lab.setIntercept(false);
    await page.getByLabel("ユーザー名").fill("nobody");
    await page.getByLabel("パスワード").fill("x");
    await page.getByRole("button", { name: "ログイン" }).click();
    await expect(lab.pane("target").getByText("ユーザーが存在しません。")).toBeVisible();

    await page.getByLabel("ユーザー名").fill("admin");
    await page.getByRole("button", { name: "ログイン" }).click();
    await expect(lab.pane("target").getByText("パスワードが違います。")).toBeVisible();
  });

  test("authentication Lv1 accepts a weak admin password", async ({ page, lab }) => {
    await lab.goto("auth");
    await lab.setIntercept(false);
    await page.getByLabel("ユーザー名").fill("admin");
    await page.getByLabel("パスワード").fill("password123");
    await page.getByRole("button", { name: "ログイン" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(page.getByText("admin としてログイン中")).toBeVisible();
  });

  test("JWT Lv1 accepts an unsigned admin token", async ({ page, lab }) => {
    await lab.goto("jwt");
    await lab.setIntercept(false);
    const token = `${encode({ alg: "none", typ: "JWT" })}.${encode({ sub: "attacker", role: "admin" })}.`;
    await page.getByLabel("raw JWT", { exact: true }).fill(token);
    await page.getByRole("button", { name: "GET /admin" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(lab.pane("target").getByText(/attacker \(admin\)/)).toBeVisible();
  });

  test("JWT editor assembles header and payload into a token", async ({ page, lab }) => {
    await lab.goto("jwt");
    await lab.setIntercept(false);
    await page.getByLabel("JWT header", { exact: true }).fill(JSON.stringify({ alg: "none", typ: "JWT" }, null, 2));
    await page.getByLabel("JWT payload", { exact: true }).fill(JSON.stringify({ sub: "attacker", role: "admin" }, null, 2));
    await page.getByLabel("JWT signature", { exact: true }).fill("");
    await page.getByRole("button", { name: "GET /admin" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
  });

  test("JWT Lv2 signs HS256 with the weak secret", async ({ page, lab }) => {
    await lab.goto("jwt");
    await lab.selectLevel(2);
    await lab.setIntercept(false);
    await page.getByLabel("JWT header", { exact: true }).fill(JSON.stringify({ alg: "HS256", typ: "JWT" }, null, 2));
    await page.getByLabel("JWT payload", { exact: true }).fill(JSON.stringify({ sub: "attacker", role: "admin" }, null, 2));
    await page.getByLabel("HMAC secret", { exact: true }).fill("secret");
    await page.getByRole("button", { name: "HS256 で署名" }).click();
    await page.getByRole("button", { name: "GET /admin" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
  });

  test("authentication Lv4 leaks the MFA code after a valid password", async ({ page, lab }) => {
    await lab.goto("auth");
    await lab.selectLevel(4);
    await lab.setIntercept(false);
    await page.getByLabel("ユーザー名").fill("admin");
    await page.getByLabel("パスワード").fill("Spring2026!");
    await page.getByRole("button", { name: "ログイン" }).click();
    await expect(lab.pane("target").getByText("パスワードは正しいですが MFA が必要です。")).toBeVisible();
    await expect(lab.pane("target").getByText(/Your MFA code is 482016/)).toBeVisible();

    await page.getByLabel("MFA コード").fill("482016");
    await page.getByRole("button", { name: "ログイン" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(page.getByText("admin としてログイン中")).toBeVisible();
  });

  test("SSRF Lv1 reaches localhost", async ({ page, lab }) => {
    await lab.goto("ssrf");
    await lab.setIntercept(false);
    await page.getByLabel("取得する URL").fill("http://localhost/admin");
    await page.getByRole("button", { name: "取得" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(lab.pane("target").getByText(/SIMULATED_SECRET/)).toBeVisible();
  });

  test("file upload Lv1 stores an executable script", async ({ page, lab }) => {
    await lab.goto("upload");
    await lab.setIntercept(false);
    await page.getByLabel("ファイル名").fill("shell.php");
    await page.getByLabel("ファイル内容").fill("<?php system('id'); ?>");
    await page.getByRole("button", { name: "アップロード" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(page.getByText("危険なファイルが実行されました。")).toBeVisible();
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
  test("IDOR: tampering with a held order id exposes Bob's order", async ({ page, lab }) => {
    await lab.goto("idor");
    await page.getByRole("button", { name: "表示" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.held);

    await lab.send("orderId", "1002");

    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(lab.pane("target").getByText(/Bob .* ORD-B0B-42/)).toBeVisible();
  });
});
