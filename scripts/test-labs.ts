/**
 * Verifies the level design of every lab:
 *  - each level's documented exploit solves that level (Lv1-4)
 *  - each level blocks the previous level's exploit (Lv2-4)
 *  - Lv5 resists every exploit
 *  - benign default input never solves anything
 * Run with: npm run test:labs
 */
import { LABS } from "../src/labs";
import type { LabInput, Level } from "../src/labs/types";

const form = (fields: string) =>
  `<form action="https://bank.example/transfer" method="post">${fields}<input name="to" value="attacker"><input name="amount" value="10000"></form><script>document.forms[0].submit()</script>`;
const noRef = '<meta name="referrer" content="no-referrer">';

const EXPLOITS: Record<string, Record<1 | 2 | 3 | 4, LabInput>> = {
  sqli: {
    1: { username: "admin'-- ", password: "x" },
    2: { username: "admin' OR '1'='1", password: "x" },
    3: { username: "admin'||'1'='1", password: "x" },
    4: { username: "admin' oorr '1'='1", password: "x" },
  },
  xss: {
    1: { comment: "<script>alert(1)</script>" },
    2: { comment: "<img src=x onerror=alert(1)>" },
    3: { comment: "<details open ontoggle=alert(1)>" },
    4: { comment: "<img src=x ononerrorerror=alert(1)>" },
  },
  cmdi: {
    1: { host: "8.8.8.8; cat flag.txt" },
    2: { host: "8.8.8.8 && cat flag.txt" },
    3: { host: "8.8.8.8\ncat flag.txt" },
    4: { host: "8.8.8.8 $(cat flag.txt)" },
  },
  path: {
    1: { name: "../../../etc/passwd" },
    2: { name: "....//....//....//etc/passwd" },
    3: { name: "..\\..\\..\\etc\\passwd" },
    4: { name: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd" },
  },
  csrf: {
    1: { html: '<img src="https://bank.example/transfer?to=attacker&amount=10000">' },
    2: { html: form("") },
    3: { html: noRef + form("") },
    4: { html: noRef + form('<input name="csrf_token" value="x">') },
  },
};

let failures = 0;
const check = (cond: boolean, msg: string) => {
  if (cond) {
    console.log(`  ok   ${msg}`);
  } else {
    failures++;
    console.log(`  FAIL ${msg}`);
  }
};

for (const lab of LABS) {
  const id = lab.meta.id;
  const exploits = EXPLOITS[id];
  console.log(`\n[${id}] ${lab.meta.title}`);
  if (!exploits) {
    check(false, "exploits defined");
    continue;
  }

  const defaults = Object.fromEntries(lab.fields.map((f) => [f.name, f.default ?? ""]));
  for (const lv of [1, 2, 3, 4, 5] as Level[]) {
    check(!lab.run(lv, defaults).solved, `Lv${lv} benign default input does not solve`);
  }

  for (const lv of [1, 2, 3, 4] as const) {
    check(lab.run(lv, exploits[lv]).solved, `Lv${lv} solved by its exploit`);
    if (lv > 1) {
      const prev = (lv - 1) as 1 | 2 | 3;
      check(!lab.run(lv, exploits[prev]).solved, `Lv${lv} blocks the Lv${prev} exploit`);
    }
  }

  for (const lv of [1, 2, 3, 4] as const) {
    check(!lab.run(5, exploits[lv]).solved, `Lv5 resists the Lv${lv} exploit`);
  }
}

console.log(failures === 0 ? "\nAll lab checks passed." : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
