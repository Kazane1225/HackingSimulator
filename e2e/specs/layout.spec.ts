import { expect, test } from "../fixtures/test";
import { SQLI_LOGIN } from "../data/intercept";
import { ROUTES } from "../data/routes";
import type { Pane } from "../data/labels";
import { horizontalOverflow } from "../support/layout";

const PANES: Pane[] = ["target", "proxy", "inspector"];

test.describe("desktop layout", () => {
  test("shows all three workbench panes and no pane tabs", async ({ lab }) => {
    await lab.goto(SQLI_LOGIN.lab);

    await expect(lab.mobileTabs).toBeHidden();
    for (const pane of PANES) await expect(lab.pane(pane)).toBeVisible();
  });

  for (const { name, path } of ROUTES) {
    test(`${name} has no horizontal overflow`, async ({ page }) => {
      await page.goto(path);
      expect(await horizontalOverflow(page)).toBeLessThanOrEqual(0);
    });
  }
});
