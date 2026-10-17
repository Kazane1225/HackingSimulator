import { expect, test } from "../fixtures/test";

test.describe("dashboard learning path", () => {
  test("shows an honest OWASP map and recommended tracks", async ({ page }) => {
    await page.goto("/#/");

    const map = page.getByTestId("owasp-map");
    await expect(map).toContainText("A01");
    await expect(map).toContainText("A02");
    await expect(map).toContainText("未対応");
    await expect(map).toContainText("カバー 9 / 隣接 1 / 未対応 0");

    await expect(page.getByTestId("track-injection")).toContainText("SQL インジェクション");
    await expect(page.getByTestId("track-access")).toContainText("IDOR");
    await expect(page.getByTestId("track-auth")).toContainText("JWT");
    await expect(page.getByTestId("track-request")).toContainText("SSRF");
    await expect(page.getByTestId("track-trust")).toContainText("暗号の失敗");
  });

  test("covered OWASP cells open a lab", async ({ page }) => {
    await page.goto("/#/");
    await page.getByTestId("owasp-map").getByRole("link", { name: /A01/ }).click();
    await expect(page).toHaveURL(/#\/lab\/idor/);
  });
});
