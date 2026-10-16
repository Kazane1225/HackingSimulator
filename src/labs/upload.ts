import type { AttackResult, Lab, LabInput, Level, LevelSpec } from "./types";

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
    executable =
      /\.(?:jpe?g|png)$/.test(filename) &&
      !filename.includes(".php.") &&
      contentType === "application/x-httpd-php" &&
      hasScript;
    reason = executable
      ? "拡張子は画像ですが、攻撃者指定の Content-Type で実行ハンドラを選びました。"
      : "許可された画像拡張子、または期待する処理形式ではありません。";
  } else if (level === 4) {
    executable =
      /\.(?:jpe?g)$/.test(filename) &&
      contentType === "image/jpeg" &&
      content.startsWith("FFD8") &&
      hasScript;
    reason = executable
      ? "先頭のマジックバイトだけを確認し、後続のスクリプトを残したまま保存しました。"
      : "拡張子・MIME・JPEG マジックバイトの検査に失敗しました。";
  } else {
    reason = "画像デコーダで再構成し、ランダム名で実行不能な別オリジンへ保存しました。";
  }

  return {
    solved: executable,
    output: [
      `filename=${filename || "(空)"}`,
      `Content-Type: ${contentType || "(なし)"}`,
      executable
        ? `[201 CREATED] /uploads/${filename}\n[EXECUTED] uid=www-data`
        : `[400/201 SAFE] ${reason}`,
    ],
    note: executable ? "アップロードした内容がサーバー側コードとして実行されました。" : reason,
  };
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
    defense: "画像拡張子を許可し二重拡張子も拒否するが、Content-Type で実行処理を選ぶ。",
    hints: [
      "Content-Type はアップロードするクライアントが指定できます。",
      "ファイル名を画像にしたまま、PHP 用 MIME を申告します。",
      "`shell.jpg` と `application/x-httpd-php` を組み合わせます。",
    ],
    solution: "`shell.jpg`、Content-Type `application/x-httpd-php`、PHP コードを送ります。",
    code: `assertAllowedExtension(name);
const handler = handlers[upload.contentType]; // クライアント値を信用
handler.save(upload);`,
  },
  4: {
    defense: "拡張子・MIME・先頭のマジックバイトを検査するが、ファイル全体を再エンコードしない。",
    hints: [
      "先頭数バイトが画像でも、後ろに別の内容を追加できます。",
      "JPEG のシグネチャの後にスクリプトを含むポリグロットを作ります。",
      "内容を `FFD8...<?php system('id'); ?>` にします。",
    ],
    solution: "`photo.jpg` / `image/jpeg` で、JPEG マジック `FFD8` の後に PHP を埋め込みます。",
    code: `if (!bytes.startsWith(JPEG_MAGIC)) deny();
saveToMisconfiguredWebRoot(bytes); // デコード・再エンコードしていない`,
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
    summary: "拡張子、Content-Type、マジックバイト検査の限界と安全な再エンコードを学ぶ。",
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
  explanation: `ファイルアップロードでは、ファイル名・拡張子・Content-Type はすべて攻撃者が変更できます。単純なブラックリストや先頭数バイトだけの検査は、二重拡張子、偽の MIME、複数形式として解釈できるポリグロットで回避されます。

業務上必要な形式だけを許可し、サイズや画像寸法を制限した上で信頼できるライブラリで完全にデコードし、新しい画像として再エンコードします。保存名はサーバーが生成し、Web サーバーの実行機能がない隔離ストレージ・別オリジンから安全な Content-Type と Content-Disposition で配信します。`,
  levels,
  run,
  exploits: {
    1: { filename: "shell.php", contentType: "application/x-httpd-php", content: "<?php system('id'); ?>" },
    2: { filename: "shell.php.jpg", contentType: "image/jpeg", content: "<?php system('id'); ?>" },
    3: { filename: "shell.jpg", contentType: "application/x-httpd-php", content: "<?php system('id'); ?>" },
    4: { filename: "photo.jpg", contentType: "image/jpeg", content: "FFD8...<?php system('id'); ?>" },
  },
};
