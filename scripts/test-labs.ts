/**
 * Verifies the level design of every lab:
 *  - each level's documented exploit solves that level (Lv1-4)
 *  - each level blocks the previous level's exploit (Lv2-4)
 *  - Lv5 resists every exploit
 *  - benign default input never solves anything
 * Run with: npm run test:labs
 */
import { LAB_UI } from "../src/components/labUI";
import { LEARNING_TRACKS, OWASP_TOP10_2021 } from "../src/curriculum";
import { GLOSSARY } from "../src/glossary";
import { LABS } from "../src/labs";
import type { Level } from "../src/labs/types";

let failures = 0;
const check = (cond: boolean, msg: string) => {
  if (cond) {
    console.log(`  ok   ${msg}`);
  } else {
    failures++;
    console.log(`  FAIL ${msg}`);
  }
};

const ids = LABS.map((l) => l.meta.id);
console.log("\n[registry]");
check(new Set(ids).size === ids.length, "lab ids are unique");
for (const id of ids) check(id in LAB_UI, `lab "${id}" has a UI definition`);
for (const id of Object.keys(LAB_UI)) check(ids.includes(id), `UI definition "${id}" belongs to a registered lab`);
for (const t of GLOSSARY) {
  for (const labId of t.labs ?? []) check(ids.includes(labId), `glossary "${t.term}" links to existing lab "${labId}"`);
}

console.log("\n[curriculum]");
const trackIds = LEARNING_TRACKS.flatMap((t) => t.labIds);
check(trackIds.length === ids.length, "track membership count matches lab count");
check(new Set(trackIds).size === trackIds.length, "each lab appears in only one track");
for (const id of trackIds) check(ids.includes(id), `track lab "${id}" exists`);
for (const id of ids) check(trackIds.includes(id), `lab "${id}" is in a learning track`);
check(OWASP_TOP10_2021.length === 10, "OWASP map lists 10 categories");
for (const cat of OWASP_TOP10_2021) {
  for (const labId of cat.labIds) check(ids.includes(labId), `OWASP ${cat.code} lab "${labId}" exists`);
  if (cat.coverage === "none") check(cat.labIds.length === 0, `OWASP ${cat.code} has no labs`);
  if (cat.coverage !== "none") check(cat.labIds.length > 0, `OWASP ${cat.code} lists labs`);
}

for (const lab of LABS) {
  const id = lab.meta.id;
  const exploits = lab.exploits;
  console.log(`\n[${id}] ${lab.meta.title}`);

  check(lab.meta.standards.cwe.length > 0, "has CWE classification");
  check(lab.meta.references.length > 0 && lab.meta.references.every((r) => r.url.startsWith("https://")), "has https references");
  for (const lv of [1, 2, 3, 4, 5] as Level[]) {
    const n = lab.levels[lv].hints.length;
    check(lv === 5 ? n >= 2 : n >= 3, `Lv${lv} has progressive hints (${n})`);
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
