import { readFile } from "node:fs/promises";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import type { AttackResult, LabInput, Level, LootItem, RealLab } from "./runner.js";

/**
 * Real path traversal lab (a "view file" endpoint) backed by a genuine
 * directory tree and node:path's own resolve/normalize algorithms, so `../`
 * handling, percent-decoding order and the join-vs-resolve footgun are real.
 *
 * The app's *virtual* world is `/var/www/files` (public) with a secret at
 * `/var/www/secret/flag.txt` and a planted `/etc/passwd`, exactly like the
 * simulated lab. Every virtual path is re-rooted into the real fixture tree
 * under lab-files/pathtraversal/ before any real fs call: nothing outside
 * that directory is ever touched, even if every check below is bypassed
 * (see `mapToReal` + the containment assertion in `readVirtual`).
 */

const VIRTUAL_BASE = "/var/www/files";
const VIRTUAL_SECRET = "/var/www/secret/flag.txt";
const VIRTUAL_TARGET = "/etc/passwd";

const LAB_FILES = process.env.LAB_FILES_DIR ?? fileURLToPath(new URL("../../lab-files/", import.meta.url));
const FIXTURE_ROOT = path.resolve(LAB_FILES, "pathtraversal");

const FLAG = "FLAG{p4th_tr4v3rs4l}";

/** Decode %XX escapes exactly once, leaving malformed sequences untouched. */
function decodeOnce(s: string): string {
  return s.replace(/%[0-9a-fA-F]{2}/g, (m) => String.fromCharCode(parseInt(m.slice(1), 16)));
}

/**
 * Historical C-library / PHP<5.3.4 behaviour: the file API stops at the
 * first NUL byte. Node's own fs rejects NUL bytes outright, so we emulate
 * the real historical truncation explicitly instead of being unable to
 * reproduce Lv3's classic poison-null-byte bypass at all.
 */
function truncateNull(s: string): string {
  const i = s.indexOf("\0");
  return i === -1 ? s : s.slice(0, i);
}

/**
 * Re-root an absolute *virtual* posix path into the real fixture tree.
 * Every branch stays inside FIXTURE_ROOT; anything not covered by the two
 * known virtual directories lands in `jail/`, which mirrors the real OS
 * root's layout only where the lab plants a fixture (currently /etc/passwd)
 * — any other absolute path simply resolves to a non-existent real file.
 */
function mapToReal(virtual: string): string {
  if (virtual === VIRTUAL_BASE || virtual.startsWith(`${VIRTUAL_BASE}/`)) {
    return path.join(FIXTURE_ROOT, "public", virtual.slice(VIRTUAL_BASE.length));
  }
  const secretDir = "/var/www/secret";
  if (virtual === secretDir || virtual.startsWith(`${secretDir}/`)) {
    return path.join(FIXTURE_ROOT, "secret", virtual.slice(secretDir.length));
  }
  return path.join(FIXTURE_ROOT, "jail", virtual.replace(/^\/+/, ""));
}

interface ReadOutcome {
  content: string | null;
  errorLine: string | null;
}

/** Real fs read with a hard jail: refuses anything that maps outside FIXTURE_ROOT. */
async function readVirtual(virtual: string): Promise<ReadOutcome> {
  const real = path.resolve(mapToReal(virtual));
  const root = path.resolve(FIXTURE_ROOT);
  if (real !== root && !real.startsWith(root + path.sep)) {
    // Defense in depth: mapToReal() should never produce this, but never
    // let a real fs call escape the fixture tree.
    return { content: null, errorLine: "DENY: jail escape blocked" };
  }
  try {
    return { content: await readFile(real, "utf8"), errorLine: null };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { content: null, errorLine: message };
  }
}

function buildOutput(raw: string, extra: string[], resolved: string): string[] {
  return [`requested : ${raw}`, ...extra, `resolved  : ${resolved}`, ""];
}

async function readResult(raw: string, resolved: string, extra: string[], target: string): Promise<AttackResult> {
  const assembled = [...extra, `readFile(${resolved})`].join("\n");
  const output = buildOutput(raw, extra, resolved);
  const { content, errorLine } = await readVirtual(resolved);
  if (content === null) {
    output.push(errorLine ?? `${resolved}: not found`);
    return { solved: false, output, assembled, note: "そのパスにファイルはありません。" };
  }
  output.push(content.replace(/\n$/, ""));
  const loot: LootItem[] | undefined =
    resolved === VIRTUAL_SECRET ? [{ id: "path-flag", label: "flag.txt", value: FLAG }] : undefined;
  const solved = resolved === target;
  const progress =
    !solved && (resolved === `${VIRTUAL_BASE}/readme.txt` || (resolved === VIRTUAL_TARGET && target === VIRTUAL_SECRET));
  const note = solved
    ? `ベースディレクトリを脱出し、${target} を読み出しました。`
    : resolved === VIRTUAL_TARGET && target !== VIRTUAL_TARGET
      ? "passwd は読めました。readme が指していた秘密ファイルはまだです。"
      : "ファイルは読めましたが、目標ではありません。";
  return {
    solved,
    output,
    assembled,
    note,
    progress,
    recap: solved
      ? ["公開フォルダの外を指すパスになった", `path の解決結果が ${resolved}`, "秘密ファイルの中身が返った"]
      : undefined,
    loot,
  };
}

async function run(level: Level, input: LabInput): Promise<AttackResult> {
  const raw = input.name ?? "";

  if (level === 5) {
    const decoded = decodeOnce(raw);
    const resolved = path.posix.resolve(VIRTUAL_BASE, decoded);
    const output = [`requested : ${raw}`, `canonical : ${resolved}`];
    const inside = resolved === VIRTUAL_BASE || resolved.startsWith(`${VIRTUAL_BASE}/`);
    if (!inside) {
      output.push(`DENY: ${resolved} はベースディレクトリ ${VIRTUAL_BASE} の外です`);
      return {
        solved: false,
        output,
        note: "正規化後のパスがベース配下か検証しているため、脱出できません。",
      };
    }
    output.push("");
    const { content, errorLine } = await readVirtual(resolved);
    output.push(content !== null ? content.replace(/\n$/, "") : (errorLine ?? `${resolved}: not found`));
    return {
      solved: false,
      output,
      note: "ベース配下のファイルのみ提供。トラバーサルは拒否されます。",
    };
  }

  if (level === 4) {
    const decoded = decodeOnce(raw);
    if (decoded.includes("..")) {
      return {
        solved: false,
        output: [`requested : ${raw}`, "DENY: path contains '..'"],
        assembled: `reject: ${raw} contains ..`,
        note: "`..` を含むパスは拒否されました。readme.txt が指す場所を、絶対パスで開けますか？",
      };
    }
    // The real Node.js footgun: path.resolve() (unlike path.join()) discards
    // the base when the second argument is absolute.
    const resolved = path.posix.resolve(VIRTUAL_BASE, decoded);
    return readResult(raw, resolved, [`resolved  : path.resolve("${VIRTUAL_BASE}", ${JSON.stringify(decoded)})`], VIRTUAL_SECRET);
  }

  if (level === 3) {
    if (!/\.txt$/i.test(raw)) {
      return {
        solved: false,
        output: [`requested : ${raw}`, "DENY: only .txt is allowed"],
        note: "拡張子の許可リストに一致しません。検査はどの文字列に対して行われていますか？",
      };
    }
    const decoded = truncateNull(decodeOnce(raw));
    const resolved = path.posix.normalize(`${VIRTUAL_BASE}/${decoded}`);
    return readResult(raw, resolved, decoded !== raw ? [`decoded   : ${decoded}`] : [], VIRTUAL_TARGET);
  }

  const filtered = level === 2 ? raw.replace(/\.\.\//g, "") : raw;
  const decoded = decodeOnce(filtered);
  const resolved = path.posix.normalize(`${VIRTUAL_BASE}/${decoded}`);
  const extra: string[] = [];
  if (filtered !== raw) extra.push(`filtered  : ${filtered}`);
  if (decoded !== filtered) extra.push(`decoded   : ${decoded}`);
  return readResult(raw, resolved, extra, VIRTUAL_TARGET);
}

export const pathtraversalRealLab: RealLab = { id: "path", run };
