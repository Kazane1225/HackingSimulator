/**
 * Cross-checks the real lab server against the simulated labs' reference
 * exploits, through the target routes (not the old scoring RPC).
 * Every Lv1-4 exploit must be visible as success in the HTTP response, Lv5
 * must resist all of them, and the benign default input must not succeed.
 * Needs a running stack: npm run real:up, then npm run test:real
 * (override the target with HACKLAB_URL, default http://localhost:8080).
 */
import { LABS } from "../src/labs";
import type { LabInput, Level } from "../src/labs/types";
import { buildLabRequest, executeLabRequest, judgeLabResponse } from "../src/realHttp";

const BASE = (process.env.HACKLAB_URL ?? "http://localhost:8080").replace(/\/$/, "");

let failures = 0;
const check = (cond: boolean, msg: string): boolean => {
  if (cond) {
    console.log(`  ok   ${msg}`);
  } else {
    failures++;
    console.log(`  FAIL ${msg}`);
  }
  return cond;
};

async function attempt(id: string, level: Level, input: LabInput) {
  const http = await executeLabRequest(`${BASE}/api`, buildLabRequest(id, level, input));
  if (http.body.includes('"solved"')) throw new Error(`${id} Lv${level}: response still carries a score payload`);
  return judgeLabResponse(id, level, input, http);
}

/**
 * The real MFA code changes with time (TOTP), so the auth Lv4 exploit has to
 * read it from the leaked debug header first, exactly like a learner would.
 */
async function realExploit(id: string, level: Level, exploit: LabInput): Promise<LabInput> {
  if (id !== "auth" || level !== 4) return exploit;
  const probe = await attempt(id, level, { ...exploit, mfaCode: "" });
  const code = probe.loot?.find((item) => item.id === "auth-mfa")?.value;
  return code ? { ...exploit, mfaCode: code } : exploit;
}

const info = (await (await fetch(`${BASE}/api/info`)).json()) as { labs: string[] };
const served = info.labs.map((lab) => lab.replace(/^\//, ""));

for (const lab of LABS) {
  const id = lab.meta.id;
  console.log(`\n[${id}] real server`);
  if (!check(served.includes(id), "has a real implementation")) continue;

  const defaults = Object.fromEntries(lab.fields.map((field) => [field.name, field.default ?? ""]));
  for (const lv of [1, 2, 3, 4, 5] as Level[]) {
    check(!(await attempt(id, lv, defaults)).solved, `Lv${lv} benign default input does not solve`);
  }
  for (const lv of [1, 2, 3, 4] as const) {
    const exploit = await realExploit(id, lv, lab.exploits[lv]);
    check((await attempt(id, lv, exploit)).solved, `Lv${lv} solved by its exploit`);
    if (lv > 1) {
      const prev = (lv - 1) as 1 | 2 | 3;
      check(!(await attempt(id, lv, lab.exploits[prev])).solved, `Lv${lv} blocks the Lv${prev} exploit`);
    }
    check(!(await attempt(id, 5, exploit)).solved, `Lv5 resists the Lv${lv} exploit`);
  }
}

console.log(failures === 0 ? "\nAll real-server checks passed." : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
