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
import { HARBOR_MISSION } from "../src/missions";
import { PATCH_LEVELS, patchOrder, reviewCode } from "../src/remediation";

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
  check(!!lab.remediation, "has remediation exercise");
  check((lab.remediation?.checklist.length ?? 0) >= 3, "remediation has review checklist");
  const cves = lab.meta.standards.cves ?? [];
  check(cves.length > 0, "has a real-world CVE example");
  for (const cve of cves) {
    check(/^CVE-\d{4}-\d{4,}$/.test(cve.id), `${cve.id} has a valid CVE id`);
    check(cve.url.startsWith("https://"), `${cve.id} has an https reference`);
    check(cve.relation === "direct" || cve.relation === "same-class", `${cve.id} declares its relation`);
  }
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

console.log("\n[remediation]");
for (const lab of LABS) {
  const id = lab.meta.id;
  const order = patchOrder(id);
  check(
    order.length === PATCH_LEVELS.length && PATCH_LEVELS.every((lv) => order.includes(lv)),
    `${id} offers each of Lv2-5 as a patch exactly once`,
  );
  for (const lv of PATCH_LEVELS) {
    const code = reviewCode(lab.levels[lv].code);
    check(code.trim() !== "" && !/\/\/ /.test(code), `${id} Lv${lv} patch has no annotating comments`);
  }
}
const secureSlots = new Set(LABS.map((lab) => patchOrder(lab.meta.id).indexOf(5)));
check(secureSlots.size >= 3, `the secure patch is spread over ${secureSlots.size} slots across labs`);

console.log("\n[mission]");
const missionIds = HARBOR_MISSION.map((step) => step.id);
check(new Set(missionIds).size === missionIds.length, "mission step ids are unique");
check(HARBOR_MISSION.every((step, index) => step.number === index + 1), "mission step numbers are sequential");
const missionLoot = new Set(["auth-mfa", "jwt-oct", "ssrf-access-key", "misconf-flag", "logging-flag"]);
for (const step of HARBOR_MISSION) {
  check(ids.includes(step.requirement.labId), `mission step "${step.id}" points to an existing lab`);
  check(step.requirement.level >= 1 && step.requirement.level <= 5, `mission step "${step.id}" has a valid level`);
  if (step.requirement.lootId) {
    check(missionLoot.has(step.requirement.lootId), `mission step "${step.id}" references known loot`);
  }
}

console.log(failures === 0 ? "\nAll lab checks passed." : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
