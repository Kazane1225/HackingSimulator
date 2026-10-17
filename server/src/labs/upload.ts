import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import * as os from "node:os";
import * as path from "node:path";
import type { AttackResult, LabInput, Level, RealLab } from "./runner.js";

/**
 * Real file-upload lab: uploaded bytes are written to a genuine per-request
 * temp directory (os.tmpdir(), always removed afterwards) and served back by
 * a real, ephemeral HTTP server (127.0.0.1 only) that classifies the request
 * the way Apache's mod_mime really does: `AddHandler php-script .php`
 * applies to *any* dot-separated extension on the filename, not just the
 * last one, which is exactly what makes "shell.php.jpg" dangerous on real
 * misconfigured hosts. The uploaded content is only ever classified, never
 * executed.
 */

const SCRIPT_MARKER = /<\?php|system\s*\(|shell_exec/i;
const JPEG_MAGIC = Buffer.from([0xff, 0xd8]);
const PNG_MAGIC = Buffer.from([0x89, 0x50]);
const JPEG_EOI = Buffer.from([0xff, 0xd9]);

/** Extensions a real `AddHandler ... .php .php3 ...` config maps to PHP. */
const HANDLER_EXTS = new Set(["php", "php3", "php4", "php5", "php7", "pht", "phtml"]);

/**
 * Decode the lab's text-based upload payload into real bytes: a leading run
 * of hex pairs (the "magic bytes", e.g. "FFD8") is hex-decoded for real;
 * the remainder is appended as literal (UTF-8) bytes, which is how the
 * polyglot payloads carry a genuine PHP tag after a genuine JPEG/PNG magic.
 */
function toBytes(content: string): Buffer {
  const m = /^(?:[0-9a-fA-F]{2})+/.exec(content);
  if (!m) return Buffer.from(content, "utf8");
  return Buffer.concat([Buffer.from(m[0], "hex"), Buffer.from(content.slice(m[0].length), "utf8")]);
}

function looksLikeImage(bytes: Buffer): boolean {
  return bytes.length >= 2 && (bytes.subarray(0, 2).equals(JPEG_MAGIC) || bytes.subarray(0, 2).equals(PNG_MAGIC));
}

/**
 * Stand-in for "decode the image and re-encode it": a real re-encoder only
 * ever emits bytes that belong to the image container, so anything appended
 * after JPEG's own End-Of-Image marker (the classic polyglot technique) is
 * dropped. Content with no valid terminator at all is not a real image and
 * is rejected (an empty buffer), exactly like a real decoder would refuse it.
 */
function reencodeImage(bytes: Buffer): Buffer {
  if (bytes.subarray(0, 2).equals(JPEG_MAGIC)) {
    const eoi = bytes.indexOf(JPEG_EOI, 2);
    return eoi === -1 ? Buffer.alloc(0) : bytes.subarray(0, eoi + 2);
  }
  // No genuine PNG samples are exercised by this lab; treat any other
  // "image" as unparsable rather than inventing PNG chunk handling.
  return Buffer.alloc(0);
}

/** All dot-separated extensions, lower-cased, exactly as mod_mime walks them. */
function allExtensions(filename: string): string[] {
  return path.basename(filename).split(".").slice(1).map((e) => e.toLowerCase());
}

/** Does an `AddHandler`/`SetHandler` target name real Apache's PHP handler? */
const PHP_HANDLER_NAME = /^(application\/x-httpd-php|php\d*-script)$/i;

/**
 * Minimal, real-syntax parser for the two directives this lab cares about.
 * `AddHandler <name> <ext...>` maps *any* of the listed extensions to
 * `<name>`, regardless of what the extension itself looks like (that is the
 * real, documented misconfiguration: `AddHandler application/x-httpd-php
 * .jpg` makes the server run .jpg files as PHP).
 */
function parsesAddsPhpHandler(content: string): boolean {
  for (const line of content.split(/\r?\n/)) {
    const add = /^\s*AddHandler\s+(\S+)\s+(.+)$/i.exec(line);
    if (add && PHP_HANDLER_NAME.test(add[1])) return true;
    if (/^\s*SetHandler\s+application\/x-httpd-php/i.test(line)) return true;
  }
  return false;
}

interface ServerConfig {
  /** Extensions mapped to the PHP handler (AddHandler), scanned across ALL dot-segments. */
  handlerExts: Set<string>;
  /** A directory-wide SetHandler (legacy misconfig): every file is parsed as PHP. */
  directoryHandler: boolean;
}

function wouldExecute(filename: string, config: ServerConfig): boolean {
  if (config.directoryHandler) return true;
  return allExtensions(filename).some((ext) => config.handlerExts.has(ext));
}

/** A real, ephemeral static file server that classifies one request and then closes. */
function serveOnce(dir: string, storedName: string, config: ServerConfig): Promise<{ handler: "php" | "static" }> {
  return new Promise((resolve, reject) => {
    let server: Server;
    server = createServer((req, res) => {
      void (async () => {
        try {
          const reqPath = decodeURIComponent(new URL(req.url ?? "/", "http://127.0.0.1").pathname).replace(/^\/+/, "");
          const real = path.resolve(dir, reqPath);
          if (real !== path.resolve(dir) && !real.startsWith(path.resolve(dir) + path.sep)) {
            res.writeHead(403).end();
            return;
          }
          await readFile(real); // confirms the file genuinely exists; bytes are never executed
          const executed = wouldExecute(reqPath, config);
          res.writeHead(200, { "X-Handler": executed ? "php" : "static" }).end();
        } catch {
          res.writeHead(404).end();
        }
      })();
    });
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      fetch(`http://127.0.0.1:${port}/${encodeURIComponent(storedName)}`)
        .then((res) => resolve({ handler: res.headers.get("x-handler") === "php" ? "php" : "static" }))
        .catch(reject)
        .finally(() => server.close());
    });
    server.unref();
  });
}

const ISOLATED_ORIGIN: ServerConfig = { handlerExts: new Set(), directoryHandler: false };

interface Decision {
  allowed: boolean;
  reason: string;
  storedName: string;
  storedBytes: Buffer;
  config: ServerConfig;
}

function decide(level: Level, filename: string, contentField: string, bytes: Buffer): Decision {
  const config: ServerConfig = { handlerExts: HANDLER_EXTS, directoryHandler: level === 3 };
  const imageExt = /\.(?:jpe?g|png|gif)$/i.test(filename);

  if (level === 1) {
    return { allowed: true, reason: "アップロードした名前のまま公開ディレクトリへ保存しました。", storedName: filename, storedBytes: bytes, config };
  }

  if (level === 2) {
    if (path.extname(filename).toLowerCase() === ".php") {
      return { allowed: false, reason: "末尾が .php のファイルは拒否されました。", storedName: filename, storedBytes: bytes, config };
    }
    return {
      allowed: true,
      reason: "末尾だけを検査し、Web サーバーは途中の .php をハンドラとして解釈しました。",
      storedName: filename,
      storedBytes: bytes,
      config,
    };
  }

  if (level === 3) {
    if (!imageExt || !looksLikeImage(bytes)) {
      return { allowed: false, reason: "画像の拡張子とマジックバイトの両方は満たしていません。", storedName: filename, storedBytes: bytes, config };
    }
    return {
      allowed: true,
      reason: "拡張子と先頭マジックは画像ですが、後続のスクリプトを残したまま保存しました（ディレクトリ全体が PHP ハンドラ経由で配信されています）。",
      storedName: filename,
      storedBytes: bytes,
      config,
    };
  }

  if (level === 4) {
    const allowed = imageExt || filename.toLowerCase().endsWith(".phtml") || filename === ".htaccess";
    if (!allowed) {
      return { allowed: false, reason: ".php は拒否されました。画像拡張子と一部のレガシー拡張子だけ許可しています。", storedName: filename, storedBytes: bytes, config };
    }
    if (imageExt) {
      const safe = reencodeImage(bytes);
      return { allowed: true, reason: "画像をデコードして再エンコードしたため、埋め込みスクリプトは消えました。", storedName: filename, storedBytes: safe, config };
    }
    if (filename === ".htaccess") {
      const addsHandler = parsesAddsPhpHandler(contentField);
      return {
        allowed: true,
        reason: addsHandler
          ? ".htaccess でハンドラを追加し、以降のアップロードが実行可能になりました。"
          : "許可された拡張子ですが、実行される内容ではありません。",
        storedName: filename,
        // AllowOverride is on: if the directive adds a PHP handler, the
        // directory now behaves like the Lv3 broad misconfig for any file.
        storedBytes: bytes,
        config: { ...config, directoryHandler: addsHandler },
      };
    }
    // .phtml: a legacy extension left in the allow-list, still handler-mapped.
    return { allowed: true, reason: "許可リストから漏れた .phtml を PHP ハンドラが実行しました。", storedName: filename, storedBytes: bytes, config };
  }

  // Level 5: the filename and claimed type are never trusted. Anything that
  // is not a genuine, fully-parsed image is rejected outright; images are
  // re-encoded and stored under a server-generated name on an isolated,
  // handler-free static origin.
  const safe = looksLikeImage(bytes) ? reencodeImage(bytes) : Buffer.alloc(0);
  return {
    allowed: safe.length > 0,
    reason:
      safe.length > 0
        ? "画像デコーダで再構成し、ランダム名で実行不能な別オリジンへ保存しました。"
        : "画像として正しく解析できなかったため、保存を拒否しました。",
    storedName: `${randomUUID()}.img`,
    storedBytes: safe,
    config: ISOLATED_ORIGIN,
  };
}

async function run(level: Level, input: LabInput): Promise<AttackResult> {
  const filename = (input.filename ?? "").trim();
  const contentType = (input.contentType ?? "").trim();
  const contentField = input.content ?? "";
  const bytes = toBytes(contentField);

  const dir = await mkdtemp(path.join(os.tmpdir(), "upload-lab-"));
  try {
    const decision = decide(level, filename, contentField, bytes);
    const output = [`filename=${filename || "(空)"}`, `Content-Type: ${contentType || "(なし)"}`];

    if (!decision.allowed) {
      output.push(`[400 REJECTED] ${decision.reason}`);
      return { solved: false, output, note: decision.reason };
    }

    // The vulnerable *handler selection* is simulated for real below; the
    // actual disk write is always confined to the per-request temp dir,
    // regardless of what the attacker puts in the filename (path separators
    // included) — matching the "never execute, always clean up" rule.
    const safeName = path.basename(decision.storedName) || "upload.bin";
    await writeFile(path.join(dir, safeName), decision.storedBytes);
    const hasScript = SCRIPT_MARKER.test(decision.storedBytes.toString("latin1"));
    const { handler } = await serveOnce(dir, safeName, decision.config);
    const executable = handler === "php" && hasScript;

    output.push(
      executable
        ? `[201 CREATED] /uploads/${safeName}\n[HTTP] X-Handler: php (uid=www-data として実行される想定)`
        : `[201 CREATED] /uploads/${safeName}\n[HTTP] X-Handler: ${handler}`,
    );
    if (decision.allowed && decision.storedBytes.length === 0 && bytes.length > 0) {
      output.push("[decode] 有効な画像として解析できず、本文は破棄されました。");
    }

    return {
      solved: executable,
      output,
      assembled: executable ? `store /uploads/${safeName} → handler=php` : `store ${safeName} → handler=${handler}`,
      note: executable ? "アップロードした内容がサーバー側コードとして実行されました。" : decision.reason,
      recap: executable
        ? ["許可された名前で保存された", "Web サーバーが PHP ハンドラとして配信した", "埋め込んだコードが実行される状態になった"]
        : undefined,
    };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export const uploadRealLab: RealLab = { id: "upload", run };
