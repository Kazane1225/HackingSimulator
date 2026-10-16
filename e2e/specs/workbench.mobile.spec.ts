import { expect, test } from "../fixtures/test";
import { SQLI_LOGIN } from "../data/intercept";
import { ROUTES } from "../data/routes";
import { STATUS, type Pane } from "../data/labels";
import { horizontalOverflow } from "../support/layout";

const PANES: Pane[] = ["target", "proxy", "inspector"];

test.describe("phone layout", () => {
  for (const { name, path } of ROUTES) {
    test(`${name} has no horizontal overflow`, async ({ page }) => {
      await page.goto(path);
      expect(await horizontalOverflow(page)).toBeLessThanOrEqual(0);
    });
  }

  test("labs and the glossary stay reachable from the tab strip", async ({ page, sidebar }) => {
    await page.goto("/#/");

    await sidebar.labLink("csrf").click();
    await expect(page).toHaveURL(/#\/lab\/csrf$/);

    await sidebar.glossaryLink().click();
    await expect(page.getByRole("heading", { name: "用語集" })).toBeVisible();
  });

  test("one workbench pane is shown at a time", async ({ lab }) => {
    await lab.goto(SQLI_LOGIN.lab);
    await expect(lab.mobileTabs).toBeVisible();

    for (const active of PANES) {
      await lab.mobileTab(active).click();
      for (const pane of PANES) {
        if (pane === active) await expect(lab.pane(pane)).toBeVisible();
        else await expect(lab.pane(pane)).toBeHidden();
      }
    }
  });

  test("an intercepted request switches to the Proxy tab", async ({ lab, sqliApp }) => {
    await lab.goto(SQLI_LOGIN.lab);
    await sqliApp.login(SQLI_LOGIN.appUser, SQLI_LOGIN.wrongPassword);

    await expect(lab.mobileTab("proxy")).toHaveAttribute("aria-selected", "true");
    await expect(lab.heldBar).toBeVisible();
    await expect(lab.statusBadge).toHaveText(STATUS.held);
  });
});
