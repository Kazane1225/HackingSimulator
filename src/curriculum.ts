/** Learning order and honest OWASP Top 10:2021 coverage. Lab ids only — look up details from `LABS`. */

export type OwaspCoverage = "covered" | "adjacent" | "none";

export interface LearningTrack {
  id: string;
  /** 1-based position in the recommended path. */
  step: number;
  title: string;
  summary: string;
  labIds: string[];
}

export interface OwaspCategory {
  code: "A01" | "A02" | "A03" | "A04" | "A05" | "A06" | "A07" | "A08" | "A09" | "A10";
  yearCode: string;
  name: string;
  coverage: OwaspCoverage;
  labIds: string[];
  note?: string;
}

export const LEARNING_TRACKS: LearningTrack[] = [
  {
    id: "injection",
    step: 1,
    title: "インジェクション",
    summary: "入力が命令として解釈される仕組みから入る",
    labIds: ["sqli", "xss", "cmdi"],
  },
  {
    id: "access",
    step: 2,
    title: "アクセス制御",
    summary: "権限と所有者の確認漏れを探す",
    labIds: ["path", "csrf", "idor"],
  },
  {
    id: "auth",
    step: 3,
    title: "認証",
    summary: "ログイン、セッション、トークンの弱点",
    labIds: ["auth", "jwt"],
  },
  {
    id: "request",
    step: 4,
    title: "リクエストとファイル",
    summary: "サーバーが出してよい宛先と受け取ってよい内容",
    labIds: ["ssrf", "upload"],
  },
  {
    id: "trust",
    step: 5,
    title: "暗号・設定・記録",
    summary: "弱い暗号、止め忘れ、古い部品、署名、ログ",
    labIds: ["crypto", "misconf", "deps", "integrity", "logging"],
  },
];

export const OWASP_TOP10_2021: OwaspCategory[] = [
  {
    code: "A01",
    yearCode: "A01:2021",
    name: "Broken Access Control",
    coverage: "covered",
    labIds: ["idor", "csrf", "path"],
  },
  {
    code: "A02",
    yearCode: "A02:2021",
    name: "Cryptographic Failures",
    coverage: "covered",
    labIds: ["crypto"],
  },
  {
    code: "A03",
    yearCode: "A03:2021",
    name: "Injection",
    coverage: "covered",
    labIds: ["sqli", "xss", "cmdi"],
  },
  {
    code: "A04",
    yearCode: "A04:2021",
    name: "Insecure Design",
    coverage: "adjacent",
    labIds: ["upload"],
    note: "ファイルアップロードで隣接。設計レビュー型のラボはない",
  },
  {
    code: "A05",
    yearCode: "A05:2021",
    name: "Security Misconfiguration",
    coverage: "covered",
    labIds: ["misconf"],
  },
  {
    code: "A06",
    yearCode: "A06:2021",
    name: "Vulnerable and Outdated Components",
    coverage: "covered",
    labIds: ["deps"],
  },
  {
    code: "A07",
    yearCode: "A07:2021",
    name: "Identification and Authentication Failures",
    coverage: "covered",
    labIds: ["auth", "jwt"],
  },
  {
    code: "A08",
    yearCode: "A08:2021",
    name: "Software and Data Integrity Failures",
    coverage: "covered",
    labIds: ["integrity"],
  },
  {
    code: "A09",
    yearCode: "A09:2021",
    name: "Security Logging and Monitoring Failures",
    coverage: "covered",
    labIds: ["logging"],
  },
  {
    code: "A10",
    yearCode: "A10:2021",
    name: "Server-Side Request Forgery",
    coverage: "covered",
    labIds: ["ssrf"],
  },
];

export const COVERAGE_LABEL: Record<OwaspCoverage, string> = {
  covered: "カバー",
  adjacent: "隣接",
  none: "未対応",
};
