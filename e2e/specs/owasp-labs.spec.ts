import { expect, test } from "../fixtures/test";
import { cryptoLab } from "../../src/labs/crypto";
import { depsLab } from "../../src/labs/deps";
import { integrityLab } from "../../src/labs/integrity";
import { loggingLab } from "../../src/labs/logging";
import { misconfLab } from "../../src/labs/misconf";
import { STATUS } from "../data/labels";

const LABS = [cryptoLab, misconfLab, depsLab, integrityLab, loggingLab];

test.describe("OWASP gap labs — simulated proxy exploits", () => {
  for (const lab of LABS) {
    for (const level of [1, 2, 3, 4] as const) {
      test(`${lab.meta.id} Lv${level} reference exploit clears the level`, async ({ lab: workbench }) => {
        await workbench.goto(lab.meta.id);
        await workbench.selectLevel(level);
        await workbench.sendAll(lab.exploits[level]);
        await expect(workbench.statusBadge).toHaveText(STATUS.success);
      });
    }

    test(`${lab.meta.id} Lv5 blocks the Lv4 exploit`, async ({ lab: workbench }) => {
      await workbench.goto(lab.meta.id);
      await workbench.selectLevel(5);
      await workbench.sendAll(lab.exploits[4]);
      await expect(workbench.statusBadge).toHaveText(STATUS.blocked);
    });
  }
});
