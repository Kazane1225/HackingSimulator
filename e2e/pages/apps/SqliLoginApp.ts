import type { Page } from "@playwright/test";
import type { LabPage } from "../LabPage";

/** Harbor's admin login, the screen for the SQL injection lab. */
export class SqliLoginApp {
  private harbor: Page | null = null;

  constructor(private readonly lab: LabPage) {}

  private async app(): Promise<Page> {
    if (this.harbor && !this.harbor.isClosed()) return this.harbor;
    this.harbor = await this.lab.openApp();
    await this.harbor.getByRole("heading", { name: "管理者ログイン" }).waitFor();
    return this.harbor;
  }

  async login(username: string, password: string) {
    const app = await this.app();
    await app.getByRole("textbox", { name: "ユーザー名" }).fill(username);
    await app.getByRole("textbox", { name: "パスワード" }).fill(password);
    await app.getByRole("button", { name: "ログイン" }).click();
  }
}
