import type { Locator, Page } from "@playwright/test";
import {
  INSPECTOR_TAB_LABELS,
  MOBILE_TAB_LABELS,
  NEXT_HINT_BUTTON,
  type InspectorTab,
  type Pane,
} from "../data/labels";
import type { Level } from "../../src/labs/types";

/** A lab screen: target app, intercepting proxy and the hint/source inspector. */
export class LabPage {
  readonly statusBadge: Locator;
  readonly heldBar: Locator;
  readonly hintItems: Locator;
  readonly nextHintButton: Locator;
  readonly solutionLocked: Locator;
  readonly mobileTabs: Locator;

  constructor(readonly page: Page) {
    this.statusBadge = page.getByTestId("status-badge");
    this.heldBar = page.getByTestId("held-bar");
    this.hintItems = page.getByTestId("hint-item");
    this.nextHintButton = page.getByRole("button", { name: NEXT_HINT_BUTTON });
    this.solutionLocked = page.getByTestId("solution-locked");
    this.mobileTabs = page.getByTestId("mobile-tabs");
  }

  async goto(labId: string) {
    await this.page.goto(`/#/lab/${labId}`);
  }

  /** Harbor, the target app, in the tab opened from the brief. */
  async openApp(): Promise<Page> {
    const popupPromise = this.page.waitForEvent("popup");
    await this.openPane("target");
    await this.pane("target").getByRole("button", { name: "アプリを開く" }).click();
    const popup = await popupPromise;
    await popup.locator(".store-tool-card").waitFor();
    return popup;
  }

  pane(name: Pane): Locator {
    return this.page.getByTestId(`pane-${name}`);
  }

  levelTab(level: Level): Locator {
    return this.page.getByRole("tab", { name: `Lv${level}`, exact: true });
  }

  async selectLevel(level: Level) {
    await this.levelTab(level).click();
  }

  /** The tab's name gains a "傍受中" suffix while a request is held. */
  mobileTab(name: Pane): Locator {
    return this.mobileTabs.getByRole("tab", { name: new RegExp(`^${MOBILE_TAB_LABELS[name]}( 傍受中)?$`) });
  }

  /** Bring a pane into view; only needed (and only possible) on narrow screens. */
  async openPane(name: Pane) {
    if (await this.mobileTabs.isVisible()) await this.mobileTab(name).click();
  }

  proxyParam(name: string): Locator {
    return this.pane("proxy").getByRole("textbox", { name, exact: true });
  }

  async ensureParam(name: string) {
    await this.openPane("proxy");
    if ((await this.proxyParam(name).count()) > 0) return;
    const box = this.pane("proxy").getByLabel("新しいパラメータ名");
    if ((await box.count()) === 0) return;
    await box.fill(name);
    await this.pane("proxy").getByRole("button", { name: "追加", exact: true }).click();
  }

  async setParam(name: string, value: string) {
    await this.ensureParam(name);
    await this.proxyParam(name).fill(value);
  }

  async forward() {
    await this.openPane("proxy");
    await this.pane("proxy").getByRole("button", { name: "Forward" }).click();
  }

  /** Tamper with one parameter in the proxy and send the request. */
  async send(name: string, value: string) {
    await this.setParam(name, value);
    await this.forward();
  }

  /** Replace several proxy fields and send. Used for multi-parameter labs. */
  async sendAll(fields: Record<string, string>) {
    await this.openPane("proxy");
    for (const [name, value] of Object.entries(fields)) {
      await this.ensureParam(name);
      await this.proxyParam(name).fill(value);
    }
    await this.forward();
  }

  async setIntercept(on: boolean) {
    await this.openPane("proxy");
    const toggle = this.pane("proxy").getByRole("checkbox", { name: /Intercept/ });
    if ((await toggle.isChecked()) !== on) await this.pane("proxy").locator("label.toggle").click();
  }

  async openInspectorTab(tab: InspectorTab) {
    await this.openPane("inspector");
    await this.pane("inspector").getByRole("tab", { name: INSPECTOR_TAB_LABELS[tab], exact: true }).click();
  }

  /**
   * Wait until the sandboxed XSS preview has rendered and given a late
   * `alert()` hook time to report, so "did not fire" can be asserted reliably.
   */
  async waitForPreviewSettled() {
    await this.page.locator("iframe.xss-frame").waitFor({ state: "attached" });
    await this.page.frameLocator("iframe.xss-frame").locator(".guest-comment").waitFor({ state: "attached" });
    await this.page.waitForTimeout(500);
  }
}
