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
@page { size: A4; margin: 10mm 11mm 10mm 11mm; }
* { box-sizing: border-box; }
html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
body { margin: 0; font: 8.1pt/1.32 "Helvetica Neue", Helvetica, Arial, sans-serif;
       color: #111; background: #fff; }
.cols { column-count: 2; column-gap: 6mm; column-fill: auto; }
h1 { font-size: 13pt; margin: 0 0 1mm; column-span: all; }
h1 + p { column-span: all; margin: 0 0 2mm; color: #333; }
h2 { font-size: 9pt; margin: 2.2mm 0 0.8mm; break-after: avoid; }
p { margin: 0 0 1.2mm; text-align: justify; hyphens: auto; }
ul { margin: 0 0 1.2mm; padding-left: 3.6mm; }
li { margin: 0 0 0.5mm; text-align: justify; hyphens: auto; }
li > input { margin: 0 1mm 0 0; vertical-align: -1px; transform: scale(0.8); }
ul:has(> li > input) { list-style: none; padding-left: 0; }
code { font: 7.2pt/1.25 Menlo, "DejaVu Sans Mono", monospace; background: #f1f1f1;
       padding: 0 0.4mm; border-radius: 1px; }
pre { margin: 0.6mm 0 1.4mm; padding: 1.2mm 1.6mm; background: #f4f4f4;
      border-left: 0.6mm solid #999; break-inside: avoid; overflow: hidden; }
pre code { font-size: 6.75pt; background: none; padding: 0; white-space: pre; }
table { border-collapse: collapse; width: 100%; margin: 0.6mm 0 1.6mm; }
th, td { border: 0.2mm solid #bbb; padding: 0.4mm 1mm; vertical-align: top;
         text-align: left; }
th { background: #e9e9e9; }
tr { break-inside: avoid; }
td { hyphens: auto; }
strong { font-weight: 600; }
`;

const md = fs.readFileSync(mdPath, 'utf8');
const body = marked.parse(md, { gfm: true });
// Keep the title and byline full width; everything else flows in two columns.
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
