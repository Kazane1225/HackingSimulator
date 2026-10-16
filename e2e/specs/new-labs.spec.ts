import { expect, test } from "../fixtures/test";
import { STATUS } from "../data/labels";

const encode = (value: object) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");

test.describe("new vulnerability labs", () => {
  test("IDOR Lv1 exposes another user's order", async ({ page, lab }) => {
    await lab.goto("idor");
    await lab.setIntercept(false);
    await page.getByLabel("注文 ID").fill("1002");
    await page.getByRole("button", { name: "注文を表示" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(lab.pane("target").getByText(/Bob .* ORD-B0B-42/)).toBeVisible();
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
    await page.getByLabel("JWT").fill(token);
    await page.getByRole("button", { name: "GET /admin" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(lab.pane("target").getByText(/attacker \(admin\)/)).toBeVisible();
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
    await page.getByLabel("Content-Type").fill("application/x-httpd-php");
    await page.getByLabel("ファイル内容").fill("<?php system('id'); ?>");
    await page.getByRole("button", { name: "アップロード" }).click();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(page.getByText("危険なファイルが実行されました。")).toBeVisible();
  });
});
