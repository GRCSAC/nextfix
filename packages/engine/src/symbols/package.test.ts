import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PackageGraph, entryCandidates, findPythonPackage, pyAdapter, resolveAcrossFiles } from './package.ts';
import { analyzePyFile } from './pyfunctions.ts';

function repo(files: Record<string, string>) {
  return new PackageGraph(async (p) => files[p]);
}

test('python package: a changed constructor method resolves through star imports to load()', async () => {
  const files: Record<string, string> = {
    'lib/yaml/__init__.py': `from .loader import *\n\n__all__ = ['load', 'full_load', 'FullLoader']\n\ndef load(stream, Loader=None):\n    if Loader is None:\n        Loader = FullLoader\n    return Loader(stream).get_single_data()\n\ndef full_load(stream):\n    return load(stream, FullLoader)\n`,
    'lib/yaml/loader.py': `from .constructor import *\nfrom .reader import *\n\n__all__ = ['FullLoader', 'SafeLoader']\n\nclass FullLoader(Reader, FullConstructor):\n    pass\n\nclass SafeLoader(Reader, SafeConstructor):\n    pass\n`,
    'lib/yaml/constructor.py': `__all__ = ['BaseConstructor', 'SafeConstructor', 'FullConstructor']\n\nclass BaseConstructor:\n    def construct_object(self, node):\n        return node\n\nclass SafeConstructor(BaseConstructor):\n    pass\n\nclass FullConstructor(SafeConstructor):\n    def set_python_instance_state(self, instance, state):\n        instance.__dict__.update(state)\n`,
    'lib/yaml/reader.py': `__all__ = ['Reader']\n\nclass Reader:\n    pass\n`,
  };
  const exists = async (p: string) => p in files;
  const found = await findPythonPackage(exists, 'lib/yaml/constructor.py');
  assert.deepEqual(found, { packageRoot: 'lib', entry: 'lib/yaml/__init__.py' });
  const g = new PackageGraph(async (p) => files[p], 200, pyAdapter('lib', analyzePyFile));
  const r = await resolveAcrossFiles(g, found!.entry, 'lib/yaml/constructor.py', new Set(['set_python_instance_state', 'FullConstructor']));
  assert.ok(r);
  assert.deepEqual([...r!.symbols.keys()].sort(), ['FullLoader', 'full_load', 'load']);
});

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
