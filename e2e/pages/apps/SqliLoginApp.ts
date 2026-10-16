import type { Locator } from "@playwright/test";
import type { LabPage } from "../LabPage";

/** SecureBank admin login, the target app of the SQL injection lab. */
export class SqliLoginApp {
  private readonly app: Locator;

  constructor(private readonly lab: LabPage) {
    this.app = lab.pane("target");
  }

  async login(username: string, password: string) {
    await this.lab.openPane("target");
    await this.app.getByRole("textbox", { name: "ユーザー名" }).fill(username);
    await this.app.getByRole("textbox", { name: "パスワード" }).fill(password);
    await this.app.getByRole("button", { name: "ログイン" }).click();
  }
}
