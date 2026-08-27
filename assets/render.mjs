import { Resvg } from '@resvg/resvg-js';
import { readFileSync, writeFileSync } from 'node:fs';
const svg = readFileSync('cover.svg', 'utf8');
const r = new Resvg(svg, {
  fitTo: { mode: 'width', value: 1200 },
  font: { loadSystemFonts: true },
  background: '#0a0f1f',
});
const png = r.render().asPng();
writeFileSync('cover.png', png);
console.log('cover.png written:', png.length, 'bytes');
