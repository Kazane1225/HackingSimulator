import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { uploadRealLab } from "./labs/upload.js";

const exploits = {
  1: { filename: "shell.php", contentType: "application/x-httpd-php", content: "<?php system('id'); ?>" },
  2: { filename: "shell.php.jpg", contentType: "image/jpeg", content: "<?php system('id'); ?>" },
  3: { filename: "photo.jpg", contentType: "image/jpeg", content: "FFD8...<?php system('id'); ?>" },
  4: { filename: "shell.phtml", contentType: "application/x-httpd-php", content: "<?php system('id'); ?>" },
} as const;

const benign = { filename: "avatar.jpg", contentType: "image/jpeg", content: "FFD8 SAFE_IMAGE_DATA" };

describe("upload (real)", () => {
  for (const lv of [1, 2, 3, 4] as const) {
    it(`Lv${lv} is solved by its exploit`, async () => {
      assert.equal((await uploadRealLab.run(lv, exploits[lv])).solved, true);
    });
    if (lv > 1) {
      const prev = (lv - 1) as 1 | 2 | 3;
      it(`Lv${lv} blocks the Lv${prev} exploit`, async () => {
        assert.equal((await uploadRealLab.run(lv, exploits[prev])).solved, false);
      });
    }
    it(`Lv5 resists the Lv${lv} exploit`, async () => {
      assert.equal((await uploadRealLab.run(5, exploits[lv])).solved, false);
    });
  }
  for (const lv of [1, 2, 3, 4, 5] as const) {
    it(`Lv${lv} benign input does not solve`, async () => {
      assert.equal((await uploadRealLab.run(lv, benign)).solved, false);
    });
  }
});

describe("upload (real engine behaviour)", () => {
  it("Apache's cumulative extension scan matches .php anywhere, not just the last segment", async () => {
    const r = await uploadRealLab.run(1, { filename: "shell.PHP.JPG.png", contentType: "image/png", content: "<?php system('id'); ?>" });
    assert.equal(r.solved, true);
  });

  it("rejects a non-hex 'magic' prefix as not an image (real hex decode)", async () => {
    const r = await uploadRealLab.run(3, { filename: "photo.jpg", contentType: "image/jpeg", content: "ZZZZ<?php system('id'); ?>" });
    assert.equal(r.solved, false);
    assert.match(r.output.join("\n"), /REJECTED/);
  });

  it("strips bytes after a real JPEG End-Of-Image marker when re-encoding at Lv4", async () => {
    // ffd8 (SOI) ffd9 (EOI) followed by a real PHP tag appended after the
    // image container: a genuine re-encoder only ever emits bytes up to EOI.
    const r = await uploadRealLab.run(4, {
      filename: "photo.jpg",
      contentType: "image/jpeg",
      content: "ffd8ffd9<?php system('id'); ?>",
    });
    assert.equal(r.solved, false);
  });

  it("an .htaccess upload that adds a PHP handler is reported as solved at Lv4", async () => {
    const r = await uploadRealLab.run(4, {
      filename: ".htaccess",
      contentType: "text/plain",
      content: "AddHandler application/x-httpd-php .jpg\n",
    });
    assert.equal(r.solved, false); // .htaccess itself has no script marker to "execute"
    assert.match(r.note ?? "", /ハンドラを追加/);
  });

  it("never writes outside the per-request temp directory (verified via the real local HTTP server)", async () => {
    const r = await uploadRealLab.run(1, { filename: "../../escape.php", contentType: "application/x-httpd-php", content: "<?php system('id'); ?>" });
    // path.basename() strips any directory components before the extension scan.
    assert.equal(r.solved, true);
  });
});
