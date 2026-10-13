// Renders SPEC.md to SPEC.pdf (A4) through Chromium and fails if it is
// longer than two pages.
//
//   cd tools && npm install && node render-spec.mjs [--html]
//
// --html also keeps the intermediate SPEC.html next to SPEC.md.
import { chromium } from 'playwright';
import { marked } from 'marked';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_PAGES = 2;
const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mdPath = path.join(repo, 'SPEC.md');
const pdfPath = path.join(repo, 'SPEC.pdf');
const htmlPath = path.join(repo, 'SPEC.html');

const css = `
@page { size: A4; margin: 12mm; }
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0; font: 9pt/1.3 "Helvetica Neue", Helvetica, Arial, sans-serif;
       color: #111; background: #fff; }
.cols { column-count: 2; column-gap: 6mm; column-fill: auto; }
h1 { font-size: 13pt; margin: 0 0 0.6mm; }
h1 + p { margin: 0 0 1.4mm; color: #333; }
h2 { font-size: 10pt; margin: 1.5mm 0 0.5mm; break-after: avoid; }
p { margin: 0 0 1mm; hyphens: auto; }
ul { margin: 0 0 1mm; padding-left: 3.4mm; }
li { margin: 0 0 0.4mm; hyphens: auto; }
li > input { margin: 0 1mm 0 0; vertical-align: -1px; transform: scale(0.8); }
ul:has(> li > input) { list-style: none; padding-left: 0; }
/* identifiers never hyphenate or wrap, so they copy and search intact */
code { font: 8.3pt/1.2 Menlo, "DejaVu Sans Mono", monospace; background: #f1f1f1;
       padding: 0 0.3mm; border-radius: 1px; hyphens: none; white-space: nowrap; }
pre { margin: 0.5mm 0 1.2mm; padding: 1mm 1.2mm; background: #f4f4f4;
      border-left: 0.6mm solid #999; break-inside: avoid; overflow: hidden; }
code.long { white-space: normal; }   /* long spans may wrap at their spaces */
pre code { font-size: 7.2pt; background: none; padding: 0; white-space: pre; }
table { border-collapse: collapse; width: 100%; margin: 0.5mm 0 1.4mm; }
table.wide { column-span: all; margin: 0.6mm 0 1.6mm; }
th, td { border: 0.2mm solid #bbb; padding: 0.3mm 0.9mm; vertical-align: top;
         text-align: left; }
th { background: #e9e9e9; }
tr { break-inside: avoid; }
td { hyphens: auto; }
strong { font-weight: 600; }
`;

const md = fs.readFileSync(mdPath, 'utf8');
// The width-defence table (HTTP/2 vs bhttp/1) spans both columns.
const body = marked.parse(md, { gfm: true })
  .replace(/<table>(\s*<thead>\s*<tr>\s*<th>Field<\/th>\s*<th>HTTP\/2 chose)/, '<table class="wide">$1')
  .replace(/(?<!<pre>)<code>([^<]{23,}?)<\/code>/g, '<code class="long">$1</code>');
// The title and byline run full width; everything else flows in two columns.
const split = body.indexOf('<h2');
const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>bhttp/1 specification</title>
<style>${css}</style></head>
<body>${body.slice(0, split)}<div class="cols">${body.slice(split)}</div></body></html>`;

const browser = await chromium.launch();
try {
  const page = await browser.newPage();
  await page.setContent(html, { waitUntil: 'load' });
  await page.pdf({ path: pdfPath, format: 'A4', printBackground: true,
                   preferCSSPageSize: true });
} finally {
  await browser.close();
}
if (process.argv.includes('--html')) fs.writeFileSync(htmlPath, html);

const pdf = fs.readFileSync(pdfPath, 'latin1');
const pages = (pdf.match(/\/Type\s*\/Page(?![s\w])/g) || []).length;
console.log(`SPEC.pdf: ${pages} page(s), ${fs.statSync(pdfPath).size} bytes`);
if (pages > MAX_PAGES) {
  console.error(`SPEC.pdf is ${pages} pages; the limit is ${MAX_PAGES}`);
  process.exit(1);
}
