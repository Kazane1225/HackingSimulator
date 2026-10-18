/** UI strings the specs assert on. Keep in sync with the app's Japanese copy. */

export const STATUS = {
  idle: "待機",
  held: "傍受中",
  success: "成功",
  failure: "失敗",
  blocked: "防御済み",
  benign: "通常応答",
  progress: "進展あり",
} as const;

export type Pane = "target" | "proxy" | "inspector";

/** Labels of the narrow-screen pane tabs. */
export const MOBILE_TAB_LABELS: Record<Pane, string> = {
  target: "状況",
  proxy: "Proxy",
  inspector: "ヒント・解説",
};

export type InspectorTab = "hint" | "source" | "solution" | "explain";

export const INSPECTOR_TAB_LABELS: Record<InspectorTab, string> = {
  hint: "ヒント",
  source: "ソース",
  solution: "解答",
  explain: "解説",
};

export const NEXT_HINT_BUTTON = "次のヒントを見る";

/** Sidebar names of the labs (`Lab.meta.shortTitle`). */
export const LAB_TITLES: Record<string, string> = {
  sqli: "SQL インジェクション",
  xss: "XSS",
  cmdi: "コマンドインジェクション",
  path: "パストラバーサル",
  csrf: "CSRF",
  idor: "IDOR",
  auth: "認証 / Session",
  jwt: "JWT",
  ssrf: "SSRF",
  upload: "Upload",
  crypto: "暗号の失敗",
  misconf: "設定ミス",
  deps: "古いコンポーネント",
  integrity: "署名なし更新",
  logging: "ログの穴",
};
