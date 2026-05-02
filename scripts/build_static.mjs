import { copyFile, mkdir, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const staticDir = join(root, "static");
const fontDir = join(staticDir, "fonts");
const jsDir = join(staticDir, "js");
const materialSymbolsCssUrl = new URL("https://fonts.googleapis.com/css2");

const icons = [
  "account_circle",
  "add",
  "all_inclusive",
  "arrow_back",
  "arrow_drop_down",
  "arrow_forward",
  "calendar_today",
  "check",
  "check_circle",
  "close",
  "cloud_upload",
  "code",
  "content_copy",
  "content_paste",
  "delete",
  "description",
  "download",
  "draft",
  "error",
  "folder",
  "folder_open",
  "group",
  "info",
  "key",
  "link",
  "lock",
  "login",
  "logout",
  "menu",
  "more_vert",
  "person",
  "person_add",
  "progress_activity",
  "refresh",
  "save",
  "search",
  "send",
  "settings",
  "share",
  "shield",
  "shield_lock",
  "swap_horiz",
  "timer",
  "upload",
  "verified_user",
  "visibility_off",
];

await mkdir(fontDir, { recursive: true });
await mkdir(jsDir, { recursive: true });
await rm(join(staticDir, "vendor"), { force: true, recursive: true });

for (const weight of [400, 500, 600, 700, 800]) {
  await copyFile(
    join(root, "node_modules", "@fontsource", "manrope", "files", `manrope-latin-${weight}-normal.woff2`),
    join(fontDir, `manrope-latin-${weight}-normal.woff2`),
  );
}

for (const weight of [400, 500]) {
  await copyFile(
    join(root, "node_modules", "@fontsource", "fira-code", "files", `fira-code-latin-${weight}-normal.woff2`),
    join(fontDir, `fira-code-latin-${weight}-normal.woff2`),
  );
}

materialSymbolsCssUrl.searchParams.set(
  "family",
  "Material Symbols Outlined:opsz,wght,FILL,GRAD@24,400,0,0",
);
materialSymbolsCssUrl.searchParams.set("icon_names", icons.join(","));

const materialCssResponse = await fetch(materialSymbolsCssUrl);
if (!materialCssResponse.ok) {
  throw new Error(`Material Symbols CSS request failed: ${materialCssResponse.status}`);
}

const materialCss = await materialCssResponse.text();
const materialFontUrl = materialCss.match(/url\(([^)]+)\)/)?.[1];
if (!materialFontUrl) {
  throw new Error("Material Symbols CSS did not include a font URL");
}

const materialFontResponse = await fetch(materialFontUrl);
if (!materialFontResponse.ok) {
  throw new Error(`Material Symbols font request failed: ${materialFontResponse.status}`);
}
await writeFile(join(fontDir, "material-symbols-outlined-subset.ttf"), Buffer.from(await materialFontResponse.arrayBuffer()));
await copyFile(join(root, "node_modules", "htmx.org", "dist", "htmx.min.js"), join(jsDir, "htmx.min.js"));
