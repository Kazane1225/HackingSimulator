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
import { LOCKED_MARK, LOGIN_LOCK_AFTER, LV1_PASSWORD, LV2_PASSWORD, PASSWORD_WORDLIST, resetLoginAttempts } from "../src/labs/auth";
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
  if (id === "auth") resetLoginAttempts();

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

  if (id === "auth") {
    check(PASSWORD_WORDLIST.length === 20, "wordlist has 20 entries");
    check(PASSWORD_WORDLIST.at(-1) === LV1_PASSWORD, "Lv1 password is the last wordlist entry");
    check(PASSWORD_WORDLIST.indexOf(LV2_PASSWORD) >= LOGIN_LOCK_AFTER, "Lv2 password sits past the lockout");
    for (const lv of [1, 2, 4] as const) {
      const hints = lab.levels[lv].hints.join("\n");
      check(!hints.includes(LV1_PASSWORD) && !hints.includes(LV2_PASSWORD), `Lv${lv} hints do not name a wordlist password`);
    }
    check(lab.levels[1].solution.includes(LV1_PASSWORD), "Lv1 solution names the password");
    check(lab.levels[2].solution.includes(LV2_PASSWORD), "Lv2 solution names the password");

    resetLoginAttempts();
    const hits = PASSWORD_WORDLIST.filter(
      (password) => lab.run(1, { username: "admin", password, sessionId: "", mfaCode: "" }).solved,
    );
    check(hits.length === 1 && hits[0] === LV1_PASSWORD, "Lv1 wordlist hits only the last entry");

    resetLoginAttempts();
    let lockedAt = -1;
    for (let i = 0; i < PASSWORD_WORDLIST.length; i++) {
      const r = lab.run(2, { username: "admin", password: PASSWORD_WORDLIST[i], sessionId: "", mfaCode: "" });
      check(!r.solved, `Lv2 entry ${i + 1} does not solve from one IP`);
      if (r.output.some((line) => line.includes(LOCKED_MARK))) {
        lockedAt = i;
        break;
      }
    }
    check(lockedAt === LOGIN_LOCK_AFTER, "Lv2 locks on the attempt after 5 failures");

    resetLoginAttempts();
    const ip = "198.51.100.40";
    for (let i = 0; i < LOGIN_LOCK_AFTER; i++) {
      const r = lab.run(2, { username: "admin", password: "nope", sessionId: "", mfaCode: "", forwardedFor: ip });
      check(!r.solved && !r.output.some((line) => line.includes(LOCKED_MARK)), `Lv2 failure ${i + 1} is not yet a lock`);
    }
    const lockedWinner = lab.run(2, { username: "admin", password: LV2_PASSWORD, sessionId: "", mfaCode: "", forwardedFor: ip });
    check(!lockedWinner.solved && lockedWinner.output.some((line) => line.includes(LOCKED_MARK)), "Lv2 hides the real password behind the lock");
    const rotated = lab.run(2, { username: "admin", password: LV2_PASSWORD, sessionId: "", mfaCode: "", forwardedFor: "198.51.100.41" });
    check(rotated.solved, "Lv2 accepts the wordlist password from a new X-Forwarded-For");
    const old = lab.run(2, { username: "admin", password: LV1_PASSWORD, sessionId: "", mfaCode: "", forwardedFor: "198.51.100.42" });
    check(!old.solved, "Lv2 rejects the Lv1 password");
  }
}

console.log(failures === 0 ? "\nAll lab checks passed." : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
