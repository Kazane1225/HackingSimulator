import { expect, test } from "../fixtures/test";
import { STATUS } from "../data/labels";

const INFO = { name: "hacklab-server", version: "0.1.0", labs: ["/sqli"] };

test.describe("real server mode", () => {
  test("is not offered when there is no lab server", async ({ page, lab }) => {
    // Static hosting answers unknown paths with index.html.
    await page.route("**/api/info", (route) =>
      route.fulfill({ status: 200, contentType: "text/html", body: "<!doctype html><html></html>" }),
    );
    await lab.goto("sqli");
    await expect(lab.pane("target")).toBeVisible();
    await expect(page.getByTestId("mode-switch")).toHaveCount(0);
  });

  test("sends the attack to the real server and shows its response", async ({ page, lab }) => {
    await page.route("**/api/info", (route) => route.fulfill({ json: INFO }));
    let username: string | null = null;
    await page.route("**/api/sqli/lv1/login", async (route) => {
      expect(route.request().method()).toBe("POST");
      username = new URLSearchParams(route.request().postData() ?? "").get("username");
      await route.fulfill({
        status: 200,
        contentType: "text/plain; charset=utf-8",
        body: "SELECT username, role FROM users WHERE username='admin'-- ';\n\n→ 1 行ヒット\n   admin  (administrator)\n",
      });
    });

    await lab.goto("sqli");
    await lab.setIntercept(false);
    await page.getByTestId("mode-switch").getByRole("button", { name: "実サーバー" }).click();
    await expect(lab.pane("proxy").locator(".raw")).toContainText("POST /sqli/lv1/login");
    await lab.send("username", "admin'-- ");

    await expect(lab.statusBadge).toHaveText(STATUS.success);
    await expect(page.getByTestId("http-response")).toContainText("admin  (administrator)");
    expect(username).toBe("admin'-- ");
  });

  test("explains a connection failure instead of hanging", async ({ page, lab }) => {
    await page.route("**/api/info", (route) => route.fulfill({ json: INFO }));
    await page.route("**/api/sqli/lv1/login", (route) => route.abort());

    await lab.goto("sqli");
    await lab.setIntercept(false);
    await page.getByTestId("mode-switch").getByRole("button", { name: "実サーバー" }).click();
    await lab.send("username", "admin");

    await expect(page.getByText(/実サーバーが起動しているか確認してください/)).toBeVisible();
    await expect(lab.statusBadge).not.toHaveText(STATUS.success);
  });
});
