import { execFile, exec } from "node:child_process";
import { fileURLToPath } from "node:url";
import type { AttackResult, LabInput, Level, RealLab } from "./runner.js";

/**
 * Real OS command injection lab: the "ping" tool is a genuine /bin/sh command
 * line, so quoting, separators and command substitution behave exactly like a
 * real shell. Objective: read flag.txt.
 *
 * Containment comes from the container (internal network, read-only rootfs,
 * non-root, resource limits); only PATH is passed to the shell's environment.
 */

const FLAG = "FLAG{c0mmand_1nj3ct10n}";
const LAB_FILES = process.env.LAB_FILES_DIR ?? fileURLToPath(new URL("../../lab-files/", import.meta.url));
const SHELL_ENV = { PATH: `${LAB_FILES}bin:/usr/local/bin:/usr/bin:/bin` };
const EXEC_OPTIONS = {
  cwd: LAB_FILES,
  env: SHELL_ENV,
  timeout: 5000,
  killSignal: "SIGKILL" as const,
  maxBuffer: 64 * 1024,
};

function stripRecursive(s: string, re: RegExp): string {
  let prev: string;
  do {
    prev = s;
    s = s.replace(re, "");
  } while (s !== prev);
  return s;
}

function wrapHost(level: Level, host: string): string {
  if (level === 1) return `ping -c 1 ${host}`;
  if (level === 2) return `ping -c 1 ${stripRecursive(host, /;/g)}`;
  if (level === 3) return `ping -c 1 "${host}"`;
  return `ping -c 1 '${host}'`;
}

interface Finished {
  text: string;
  failed: boolean;
}

function collect(error: Error | null, stdout: string, stderr: string): Finished {
  const text = `${stdout}${stderr}`.replace(/\s+$/, "");
  if (error && text === "") return { text: `(${error.message})`, failed: true };
  return { text, failed: error !== null };
}

function viaShell(command: string): Promise<Finished> {
  return new Promise((resolve) => {
    exec(command, { ...EXEC_OPTIONS, shell: "/bin/sh" }, (error, stdout, stderr) => resolve(collect(error, stdout, stderr)));
  });
}

function direct(file: string, args: string[]): Promise<Finished> {
  return new Promise((resolve) => {
    execFile(file, args, EXEC_OPTIONS, (error, stdout, stderr) => resolve(collect(error, stdout, stderr)));
  });
}

async function run(level: Level, input: LabInput): Promise<AttackResult> {
  const host = input.host ?? "";

  if (level === 5) {
    const output = ["// 入力をシェルに渡す前に厳格に検証"];
    if (!/^[A-Za-z0-9.\-]+$/.test(host)) {
      output.push(`reject: "${host}" はホスト名/IP として不正です`);
      return {
        solved: false,
        output,
        note: "許可文字のみのホスト名だけを受け付け、シェルを経由しません。注入の余地がありません。",
      };
    }
    const assembled = `execFile("ping", ["-c", "1", ${JSON.stringify(host)}])`;
    output.push(`${assembled}  // 配列で直接実行`);
    const done = await direct(`${LAB_FILES}bin/ping`, ["-c", "1", host]);
    if (done.text) output.push(...done.text.split("\n"));
    return {
      solved: false,
      output,
      assembled,
      benign: true,
      note: "正当なホスト名のため ping のみ実行。コマンド注入はできません。",
    };
  }

  const command = wrapHost(level, host);
  const done = await viaShell(command);
  const output = [`$ ${command}`];
  if (done.text) output.push(...done.text.split("\n"));
  const leaked = done.text.includes(FLAG);

  return {
    solved: leaked,
    output,
    assembled: command,
    note: leaked
      ? "注入したコマンドが実行され、flag.txt を読み出しました。"
      : "注入は失敗しました。ping しか実行されていません。",
    recap: leaked
      ? ["入力がシェルの構文として解釈された", "ping 以外のコマンドが走った", "flag.txt の中身が出力された"]
      : undefined,
    loot: leaked ? [{ id: "cmdi-flag", label: "flag.txt", value: FLAG }] : undefined,
  };
}

export const cmdiRealLab: RealLab = { id: "cmdi", run };
