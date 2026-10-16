import { writeFileSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { chromium } from "playwright";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const svg = readFileSync(join(root, "public", "favicon.svg"), "utf8");

function icoFromPngs(images) {
  const count = images.length;
  const header = Buffer.alloc(6 + 16 * count);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(count, 4);
  let offset = header.length;
  const chunks = [header];
  images.forEach((img, i) => {
    const entry = 6 + 16 * i;
    header.writeUInt8(img.size >= 256 ? 0 : img.size, entry);
    header.writeUInt8(img.size >= 256 ? 0 : img.size, entry + 1);
    header.writeUInt8(0, entry + 2);
    header.writeUInt8(0, entry + 3);
    header.writeUInt16LE(1, entry + 4);
    header.writeUInt16LE(32, entry + 6);
    header.writeUInt32LE(img.png.length, entry + 8);
    header.writeUInt32LE(offset, entry + 12);
    chunks.push(img.png);
    offset += img.png.length;
  });
  return Buffer.concat(chunks);
}

const browser = await chromium.launch();
const pngs = [];
for (const size of [16, 32, 48, 256]) {
  const page = await browser.newPage({ viewport: { width: size, height: size }, deviceScaleFactor: 1 });
  await page.setContent(
    `<!doctype html><html><head><style>*{margin:0;padding:0}html,body{width:${size}px;height:${size}px;overflow:hidden}svg{display:block;width:${size}px;height:${size}px}</style></head><body>${svg}</body></html>`,
    { waitUntil: "load" },
  );
  const png = await page.screenshot({ type: "png", omitBackground: false });
  pngs.push({ size, png });
  await page.close();
}
await browser.close();

writeFileSync(join(root, "public", "icon-256.png"), pngs.find((p) => p.size === 256).png);
writeFileSync(join(root, "public", "favicon.ico"), icoFromPngs(pngs));
console.log("wrote public/favicon.ico and public/icon-256.png");
