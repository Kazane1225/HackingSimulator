import { expect, test } from "../fixtures/test";
import { SQLI_LOGIN } from "../data/intercept";
import { seedProgress } from "../support/storage";

test.describe("shared target app", () => {
  test("keeps cleared results in Harbor while the lab pane stays a brief", async ({ page, lab }) => {
    await seedProgress(
      page,
      JSON.stringify({ sqli: [1], idor: [1], crypto: [1], csrf: [1], auth: [4], upload: [1] }),
    );
    await lab.goto("xss");

    const brief = lab.pane("target");
    await expect(brief.getByRole("heading", { name: "開いた人の画面で動かす" })).toBeVisible();
    await expect(brief.getByRole("heading", { name: "状況" })).toBeVisible();
    await expect(brief.getByTestId("target-app")).toHaveCount(0);

    const app = await lab.openApp();
    await app.getByRole("button", { name: "ホーム" }).click();
    await expect(app.getByTestId("store-account")).toHaveText("admin");
    await expect(app.getByTestId("store-balance")).toHaveText("¥990,000");
    await expect(app.getByTestId("store-orders")).toContainText("法人向けセキュリティキー");
    await expect(app.getByTestId("store-orders")).toContainText("4242424242424242");
    await expect(app.getByTestId("store-avatar")).toHaveText("画像");
    await app.getByRole("button", { name: "受信箱" }).click();
    await expect(app.getByTestId("store-mail")).toContainText("482016");
  });

  test("a fresh sqli level stays a login while the account stays admin", async ({ page, lab }) => {
    await seedProgress(page, JSON.stringify({ sqli: [1] }));
    await lab.goto("sqli");

    await expect(lab.levelTab(2)).toHaveAttribute("aria-selected", "true");
    await expect(lab.pane("target").getByRole("heading", { name: "管理者の席に入る" })).toBeVisible();

    const app = await lab.openApp();
    await expect(app.getByTestId("store-account")).toHaveText("admin");
    await expect(app.getByRole("heading", { name: "管理者ログイン" })).toBeVisible();
  });

  test("opens Harbor in another tab", async ({ page, lab }) => {
    await seedProgress(page, JSON.stringify({ sqli: [1], idor: [1] }));
    await lab.goto("xss");
    const popup = await lab.openApp();
    await expect(popup).toHaveTitle("Harbor");
    await expect(popup.getByRole("heading", { name: "みんなのゲストブック" }).first()).toBeVisible();
    await popup.getByRole("button", { name: "ホーム" }).click();
    await expect(popup.getByTestId("store-account")).toHaveText("admin");
    await popup.getByRole("button", { name: "注文" }).click();
    await expect(popup.getByTestId("store-orders")).toContainText("法人向けセキュリティキー");
  });

  test("solving sqli shows admin in Harbor on the next lab", async ({ lab }) => {
    await lab.goto(SQLI_LOGIN.lab);
    const app = await lab.openApp();
    await expect(app.getByTestId("store-account")).toHaveText("alice");

    await lab.send(SQLI_LOGIN.usernameParam, SQLI_LOGIN.tamperedUsername);
    await expect(app.getByTestId("store-account")).toHaveText("admin");

    await lab.goto("cmdi");
    await expect(app.getByTestId("store-account")).toHaveText("admin");
    await expect(app.getByRole("heading", { name: "到達性テスト (ping)" })).toBeVisible();
  });
});
