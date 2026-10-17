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
    let posted: { level: number; input: Record<string, string> } | undefined;
    await page.route("**/api/sqli/run", async (route) => {
      posted = route.request().postDataJSON();
      await route.fulfill({
        json: {
          solved: true,
          output: ["SELECT username, role FROM users WHERE username='admin'-- ';", "", "→ 1 行ヒット", "   admin  (administrator)"],
          assembled: "SELECT username, role FROM users WHERE username='admin'-- ';",
          note: "admin としてログイン成功。認証をバイパスしました。",
        },
      });
    });

    await lab.goto("sqli");
    await lab.setIntercept(false);
    await page.getByTestId("mode-switch").getByRole("button", { name: "実サーバー" }).click();
    await lab.send("username", "admin'-- ");

    await expect(lab.statusBadge).toHaveText(STATUS.success);
    expect(posted?.level).toBe(1);
    expect(posted?.input.username).toBe("admin'-- ");
  });

  test("explains a connection failure instead of hanging", async ({ page, lab }) => {
    await page.route("**/api/info", (route) => route.fulfill({ json: INFO }));
    await page.route("**/api/sqli/run", (route) => route.abort());

    await lab.goto("sqli");
    await lab.setIntercept(false);
    await page.getByTestId("mode-switch").getByRole("button", { name: "実サーバー" }).click();
    await lab.send("username", "admin");

    await expect(page.getByText(/実サーバーが起動しているか確認してください/)).toBeVisible();
    await expect(lab.statusBadge).not.toHaveText(STATUS.success);
  });
});
