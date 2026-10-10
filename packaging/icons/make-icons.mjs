// Renders the NextFix mark into nextfix.ico (16, 24, 32, 48, 64, 128, 256) and nextfix-256.png.
//
//   node packaging/icons/make-icons.mjs
//
// No dependencies: the mark in docs/brand/logo.svg is a single straight-edged polygon (the
// bold N whose diagonal reads as a chevron), so it is rasterised here directly, with the same
// three-stop diagonal gradient the SVG uses, on a rounded Navy-to-Midnight tile so the icon
// reads on light and dark taskbars alike. PNG and ICO are written by hand (zlib comes from
// node:zlib). Sizes up to 128 are stored as 32-bit BMP entries, 256 as PNG, which is the layout
// every Windows version since Vista accepts and the one Inno Setup and Explorer render best.
//
// Re-run after changing docs/brand/logo.svg or the colours in docs/BRAND.md and commit the
// outputs: the installer (packaging/windows/nextfix.iss) embeds nextfix.ico at build time.

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { deflateSync } from 'node:zlib';

const outDir = import.meta.dirname;
const SIZES = [16, 24, 32, 48, 64, 128, 256];

// docs/BRAND.md
const MIDNIGHT = [0x0b, 0x12, 0x20];
const NAVY = [0x0f, 0x1f, 0x3d];
// docs/brand/logo.svg, gradient nf-g: x1=0 y1=0 x2=1 y2=1 in the mark's bounding box.
const GRADIENT = [
  [0.0, [0x60, 0xa5, 0xfa]],
  [0.55, [0x3b, 0x82, 0xf6]],
  [1.0, [0x1d, 0x4e, 0xd8]],
];

// The mark from logo.svg, "M6 80V0h18l34 46V0h18v80H58L24 34v46z", as vertices in an 80x80 box.
const MARK = [
  [6, 80], [6, 0], [24, 0], [58, 46], [58, 0], [76, 0], [76, 80], [58, 80], [24, 34], [24, 80],
];
const MARK_BOX = { x: 6, y: 0, w: 70, h: 80 };

function gradientAt(t) {
  const c = Math.min(1, Math.max(0, t));
  for (let i = 1; i < GRADIENT.length; i++) {
    const [t0, c0] = GRADIENT[i - 1];
    const [t1, c1] = GRADIENT[i];
    if (c <= t1) {
      const f = (c - t0) / (t1 - t0);
      return c0.map((v, k) => v + (c1[k] - v) * f);
    }
  }
  return GRADIENT[GRADIENT.length - 1][1];
}

function insidePolygon(px, py, poly) {
  // Even-odd ray cast; the mark does not self-intersect so even-odd and non-zero agree.
  let inside = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i];
    const [xj, yj] = poly[j];
    if ((yi > py) !== (yj > py) && px < ((xj - xi) * (py - yi)) / (yj - yi) + xi) inside = !inside;
  }
  return inside;
}

function insideRoundedSquare(px, py, size, radius) {
  const x = Math.min(px, size - px);
  const y = Math.min(py, size - py);
  if (x >= radius || y >= radius) return x >= 0 && y >= 0;
  const dx = radius - x;
  const dy = radius - y;
  return dx * dx + dy * dy <= radius * radius;
}

/** Returns straight (non-premultiplied) RGBA bytes, row-major, top-down. */
function render(size) {
  const ss = size <= 64 ? 8 : 4; // supersampling per axis
  const samples = ss * ss;
  const radius = size * 0.22;
  const markH = size * 0.6;
  const scale = markH / MARK_BOX.h;
  const markW = MARK_BOX.w * scale;
  const ox = (size - markW) / 2 - MARK_BOX.x * scale;
  const oy = (size - markH) / 2 - MARK_BOX.y * scale;
  const poly = MARK.map(([x, y]) => [x * scale + ox, y * scale + oy]);
  const out = Buffer.alloc(size * size * 4);
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let r = 0, g = 0, b = 0, a = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const px = x + (sx + 0.5) / ss;
          const py = y + (sy + 0.5) / ss;
          if (!insideRoundedSquare(px, py, size, radius)) continue;
          let c;
          if (insidePolygon(px, py, poly)) {
            const u = (px - ox - MARK_BOX.x * scale) / markW;
            const v = (py - oy - MARK_BOX.y * scale) / markH;
            c = gradientAt((u + v) / 2);
          } else {
            const f = py / size;
            c = NAVY.map((n, k) => n + (MIDNIGHT[k] - n) * f);
          }
          r += c[0]; g += c[1]; b += c[2]; a += 1;
        }
      }
      const i = (y * size + x) * 4;
      if (a === 0) continue;
      out[i] = Math.round(r / a);
      out[i + 1] = Math.round(g / a);
      out[i + 2] = Math.round(b / a);
      out[i + 3] = Math.round((a / samples) * 255);
    }
  }
  return out;
}

// --- PNG ----------------------------------------------------------------------------------
const CRC_TABLE = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}
function png(rgba, size) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0; // filter: none
    rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// --- ICO ----------------------------------------------------------------------------------
function bmpEntry(rgba, size) {
  // BITMAPINFOHEADER with doubled height, 32-bit BGRA rows bottom-up, then a 1-bit AND mask
  // padded to 4-byte rows (set for fully transparent pixels, for renderers that ignore alpha).
  const maskRow = Math.ceil(size / 32) * 4;
  const header = Buffer.alloc(40);
  header.writeUInt32LE(40, 0);
  header.writeInt32LE(size, 4);
  header.writeInt32LE(size * 2, 8);
  header.writeUInt16LE(1, 12);
  header.writeUInt16LE(32, 14);
  header.writeUInt32LE(0, 16);
  header.writeUInt32LE(size * size * 4 + maskRow * size, 20);
  const xor = Buffer.alloc(size * size * 4);
  const and = Buffer.alloc(maskRow * size);
  for (let y = 0; y < size; y++) {
    const srcRow = size - 1 - y;
    for (let x = 0; x < size; x++) {
      const s = (srcRow * size + x) * 4;
      const d = (y * size + x) * 4;
      xor[d] = rgba[s + 2];
      xor[d + 1] = rgba[s + 1];
      xor[d + 2] = rgba[s];
      xor[d + 3] = rgba[s + 3];
      if (rgba[s + 3] === 0) and[y * maskRow + (x >> 3)] |= 0x80 >> (x & 7);
    }
  }
  return Buffer.concat([header, xor, and]);
}

function ico(images) {
  const count = images.length;
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(count, 4);
  const dir = Buffer.alloc(16 * count);
  let offset = 6 + 16 * count;
  const blobs = [];
  images.forEach(({ size, data }, i) => {
    const e = i * 16;
    dir[e] = size >= 256 ? 0 : size;
    dir[e + 1] = size >= 256 ? 0 : size;
    dir[e + 2] = 0; // palette
    dir[e + 3] = 0;
    dir.writeUInt16LE(1, e + 4);
    dir.writeUInt16LE(32, e + 6);
    dir.writeUInt32LE(data.length, e + 8);
    dir.writeUInt32LE(offset, e + 12);
    offset += data.length;
    blobs.push(data);
  });
  return Buffer.concat([header, dir, ...blobs]);
}

const images = SIZES.map((size) => {
  const rgba = render(size);
  return { size, data: size >= 256 ? png(rgba, size) : bmpEntry(rgba, size), rgba };
});
writeFileSync(join(outDir, 'nextfix.ico'), ico(images));
const big = images.find((i) => i.size === 256);
writeFileSync(join(outDir, 'nextfix-256.png'), png(big.rgba, 256));
console.log(`wrote nextfix.ico (${SIZES.join(', ')}) and nextfix-256.png`);
