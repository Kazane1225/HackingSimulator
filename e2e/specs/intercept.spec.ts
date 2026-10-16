import { expect, test } from "../fixtures/test";
import { STATUS } from "../data/labels";
import { SQLI_LOGIN } from "../data/intercept";

test.describe("intercepting proxy flow (SQLi login)", () => {
  test.beforeEach(async ({ lab }) => {
    await lab.goto(SQLI_LOGIN.lab);
  });

  test("a submission is held, then forwarded unchanged", async ({ lab, sqliApp }) => {
    await sqliApp.login(SQLI_LOGIN.appUser, SQLI_LOGIN.wrongPassword);

    await expect(lab.heldBar).toBeVisible();
    await expect(lab.statusBadge).toHaveText(STATUS.held);

    await lab.forward();

    await expect(lab.heldBar).toBeHidden();
    await expect(lab.statusBadge).toHaveText(STATUS.failure);
  });

  test("tampering with a held request changes the outcome", async ({ lab, sqliApp }) => {
    await sqliApp.login(SQLI_LOGIN.appUser, SQLI_LOGIN.wrongPassword);
    await expect(lab.statusBadge).toHaveText(STATUS.held);

    await lab.send(SQLI_LOGIN.usernameParam, SQLI_LOGIN.tamperedUsername);

    await expect(lab.statusBadge).toHaveText(STATUS.success);
  });

  test("with Intercept off the request goes straight through", async ({ lab, sqliApp }) => {
    await lab.setIntercept(false);
    await sqliApp.login(SQLI_LOGIN.tamperedUsername, SQLI_LOGIN.wrongPassword);

    await expect(lab.heldBar).toBeHidden();
    await expect(lab.statusBadge).toHaveText(STATUS.success);
  });
});
