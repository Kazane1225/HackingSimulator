import { expect, test } from "../fixtures/test";
import { SQLI_LOGIN } from "../data/intercept";
import { seedProgress } from "../support/storage";

test.describe("shared target app", () => {
  test("keeps cleared results visible on another lab's screen", async ({ page, lab }) => {
    await seedProgress(
      page,
      JSON.stringify({ sqli: [1], idor: [1], crypto: [1], csrf: [1], auth: [4], upload: [1] }),
    );
    await lab.goto("xss");

    const app = lab.pane("target").getByTestId("target-app");
    await expect(app.getByTestId("target-account")).toHaveText("admin");
    await expect(app.getByTestId("target-balance")).toHaveText("¥990,000");
    await expect(app.getByTestId("target-orders")).toContainText("法人向けセキュリティキー");
    await expect(app.getByTestId("target-orders")).toContainText("4242424242424242");
    await expect(app.getByTestId("target-mail")).toContainText("482016");
    await expect(app.getByTestId("target-avatar")).toHaveText("画像");
  });

  test("a fresh sqli level stays logged out while the account bar keeps admin", async ({ page, lab }) => {
    await seedProgress(page, JSON.stringify({ sqli: [1] }));
    await lab.goto("sqli");

    await expect(lab.levelTab(2)).toHaveAttribute("aria-selected", "true");
    await expect(lab.pane("target").getByTestId("target-account")).toHaveText("admin");
    await expect(lab.pane("target").getByRole("heading", { name: "管理者ログイン" })).toBeVisible();
  });

  test("opens the target app in another tab", async ({ page, lab }) => {
    await seedProgress(page, JSON.stringify({ sqli: [1], idor: [1] }));
    await lab.goto("xss");
    const popupPromise = page.waitForEvent("popup");
    await lab.pane("target").getByRole("button", { name: "アプリを開く" }).click();
    const popup = await popupPromise;
    await expect(popup).toHaveTitle("Harbor");
    await expect(popup.getByRole("heading", { name: "みんなのゲストブック" }).first()).toBeVisible();
    await popup.getByRole("button", { name: "ホーム" }).click();
    await expect(popup.getByTestId("store-account")).toHaveText("admin");
    await popup.getByRole("button", { name: "注文" }).click();
    await expect(popup.getByTestId("store-orders")).toContainText("法人向けセキュリティキー");
  });

  test("solving sqli shows admin on the next lab", async ({ lab }) => {
    await lab.goto(SQLI_LOGIN.lab);
    await expect(lab.pane("target").getByTestId("target-account")).toHaveText("alice");

    await lab.send(SQLI_LOGIN.usernameParam, SQLI_LOGIN.tamperedUsername);
    await expect(lab.pane("target").getByTestId("target-account")).toHaveText("admin");

    await lab.goto("cmdi");
    await expect(lab.pane("target").getByTestId("target-account")).toHaveText("admin");
    await expect(lab.pane("target").getByRole("heading", { name: "到達性テスト (ping)" })).toBeVisible();
  });
});
