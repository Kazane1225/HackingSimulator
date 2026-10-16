/** Every page that must render without horizontal overflow on a phone. */
export const ROUTES: { name: string; path: string }[] = [
  { name: "dashboard", path: "/#/" },
  { name: "sqli lab", path: "/#/lab/sqli" },
  { name: "xss lab", path: "/#/lab/xss" },
  { name: "cmdi lab", path: "/#/lab/cmdi" },
  { name: "path traversal lab", path: "/#/lab/path" },
  { name: "csrf lab", path: "/#/lab/csrf" },
  { name: "glossary", path: "/#/glossary" },
];
