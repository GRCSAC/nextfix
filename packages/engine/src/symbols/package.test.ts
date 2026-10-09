import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PackageGraph, entryCandidates, resolveAcrossFiles } from './package.ts';

function repo(files: Record<string, string>) {
  return new PackageGraph(async (p) => files[p]);
}

test('esm barrel: a changed internal function resolves to the entry export that reaches it', async () => {
  const g = repo({
    'src/index.js': `import { Lexer } from './Lexer.js';\nexport function marked(src) { return new Lexer().lex(src); }\nmarked.parse = marked;\nexport const parse = marked;\n`,
    'src/Lexer.js': `import { block } from './rules.js';\nexport class Lexer { lex(src) { return block.exec(src); } }\n`,
    'src/rules.js': `export const block = { exec() {} };\nexport const inline = {};\n`,
  });
  // the fix touched `block` in rules.js (module-level)
  const r = await resolveAcrossFiles(g, 'src/index.js', 'src/rules.js', new Set(['block']));
  assert.ok(r);
  assert.deepEqual([...r!.symbols.keys()].sort(), ['marked', 'parse']);
});

test('cjs main re-exporting a lib file: changed function maps to the public name', async () => {
  const g = repo({
    'index.js': `module.exports = require('./lib/index');\n`,
    'lib/index.js': `const { getLocale, defineLocale } = require('./locales');\nconst hooks = {};\nhooks.locale = getLocale;\nhooks.defineLocale = defineLocale;\nmodule.exports = hooks;\n`,
    'lib/locales.js': `function loadLocale(name) { return require('./locale/' + name); }\nfunction getLocale(key) { return loadLocale(key); }\nfunction defineLocale(n, c) { return c; }\nmodule.exports = { getLocale, defineLocale };\n`,
  });
  const r = await resolveAcrossFiles(g, 'index.js', 'lib/locales.js', new Set(['loadLocale']));
  assert.ok(r);
  assert.deepEqual([...r!.symbols.keys()], ['locale']);
});

test('export * barrel and a namespace import', async () => {
  const g = repo({
    'src/index.ts': `import * as util from './util';\nexport * from './api';\nexport function run(x: string) { return util.clean(x); }\n`,
    'src/api.ts': `import { clean } from './util';\nexport function sanitize(s: string) { return clean(s); }\nexport function other() { return 1; }\n`,
    'src/util.ts': `export function clean(s: string) { return s; }\nexport function unrelated() {}\n`,
  });
  const r = await resolveAcrossFiles(g, 'src/index.ts', 'src/util.ts', new Set(['clean']));
  assert.ok(r);
  assert.deepEqual([...r!.symbols.keys()].sort(), ['run', 'sanitize']);
});

test('entry candidates prefer source files over built ones', () => {
  const c = entryCandidates({ name: 'marked', main: './lib/marked.cjs', module: './lib/marked.esm.js', exports: { '.': { import: './lib/marked.esm.js', default: './lib/marked.cjs' } } }, 'marked');
  assert.ok(c.indexOf('src/marked.js') < c.indexOf('lib/marked.esm.js'));
  assert.ok(c.includes('lib/marked.cjs'));
});
