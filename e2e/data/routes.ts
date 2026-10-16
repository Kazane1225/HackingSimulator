/** Every page that must render without horizontal overflow on a phone. */
export const ROUTES: { name: string; path: string }[] = [
  { name: "dashboard", path: "/#/" },
  { name: "sqli lab", path: "/#/lab/sqli" },
  { name: "xss lab", path: "/#/lab/xss" },
  { name: "cmdi lab", path: "/#/lab/cmdi" },
  { name: "path traversal lab", path: "/#/lab/path" },
  { name: "csrf lab", path: "/#/lab/csrf" },
  { name: "idor lab", path: "/#/lab/idor" },
  { name: "authentication lab", path: "/#/lab/auth" },
  { name: "jwt lab", path: "/#/lab/jwt" },
  { name: "ssrf lab", path: "/#/lab/ssrf" },
  { name: "file upload lab", path: "/#/lab/upload" },
  { name: "glossary", path: "/#/glossary" },
];
