import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseUnifiedDiff, sourceFiles } from './diff.ts';
import { fixCandidates, diffUrl, rawRef } from './fixcommits.ts';
import { analyzeFile, enclosing, enclosingAll, resolvePublic } from './functions.ts';

const DIFF = `diff --git a/lib/response.js b/lib/response.js
index 1111111..2222222 100644
--- a/lib/response.js
+++ b/lib/response.js
@@ -10,7 +10,8 @@ res.redirect = function redirect(url) {
   var address = url;
-  address = encodeUrl(address);
+  address = this.location(address).get('Location');
+  // extra
   return address;
 };
diff --git a/test/res.redirect.js b/test/res.redirect.js
--- a/test/res.redirect.js
+++ b/test/res.redirect.js
@@ -1,2 +1,3 @@
 a
+b
 c
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1 +1,2 @@
 x
+y
`;

test('unified diff parser maps added and deleted lines to new-file positions', () => {
  const files = parseUnifiedDiff(DIFF);
  assert.equal(files.length, 3);
  const src = sourceFiles(files);
  assert.deepEqual(src.map((f) => f.path), ['lib/response.js']);
  assert.deepEqual(src[0]!.hunks[0]!.touchedNewLines, [11, 12]);
});

test('fix candidates rank FIX-typed commits in the matching repo first', () => {
  const c = fixCandidates(
    [
      { type: 'WEB', url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-29041' },
      { type: 'WEB', url: 'https://github.com/expressjs/express/pull/5539' },
      { type: 'FIX', url: 'https://github.com/expressjs/express/commit/0867302ddbde0e9463d0564fea5861feb708c2dd' },
      { type: 'WEB', url: 'https://github.com/koajs/koa/issues/1800' },
    ],
    'express',
  );
  assert.equal(c[0]!.kind, 'commit');
  assert.equal(c[0]!.ref, '0867302ddbde0e9463d0564fea5861feb708c2dd');
  assert.equal(c[0]!.repoMatch, true);
  assert.equal(diffUrl(c[0]!), 'https://github.com/expressjs/express/commit/0867302ddbde0e9463d0564fea5861feb708c2dd.diff');
  assert.equal(c[1]!.kind, 'pull');
  assert.equal(rawRef(c[1]!), 'refs/pull/5539/head');
});

test('changed internal functions resolve to their public callers', () => {
  const src = `
function setKey(obj, keys, value) { obj[keys[0]] = value; }
function parse(args) { var out = {}; setKey(out, ['a'], 1); return out; }
module.exports = function minimist(args) { return parse(args); };
`;
  const facts = analyzeFile(src, 'index.js');
  const fn = enclosing(facts, 2)!;
  assert.equal(fn.name, 'setKey');
  const pubs = resolvePublic(facts, fn);
  assert.deepEqual([...pubs.keys()], ['default']);
  assert.equal(pubs.get('default'), 'caller:minimist');
  assert.equal(facts.defaultIsFunction, true);
});

test('lodash-style namespace assignment and express-style method assignment are public', () => {
  const lodash = `
function template(string, options) { return string + options; }
function baseSet(object, path, value) { return object; }
function set(object, path, value) { return baseSet(object, path, value); }
lodash.template = template;
lodash.set = set;
`;
  const f1 = analyzeFile(lodash, 'lodash.js');
  assert.deepEqual([...resolvePublic(f1, enclosing(f1, 2)!).keys()], ['template']);
  assert.deepEqual([...resolvePublic(f1, enclosing(f1, 3)!).keys()], ['set']);

  const express = `
var res = Object.create(null);
module.exports = res;
res.redirect = function redirect(url) { this.location(url); };
res.location = function location(url) { return url; };
`;
  const f2 = analyzeFile(express, 'lib/response.js');
  assert.deepEqual([...resolvePublic(f2, enclosing(f2, 4)!).keys()], ['redirect']);
  // location is public, and redirect (also public) calls it: both reach the vulnerable code.
  assert.deepEqual([...resolvePublic(f2, enclosing(f2, 5)!).keys()], ['location', 'redirect']);
});

test('a change inside a nested callback resolves to the owning public function', () => {
  const src = `
var res = {};
module.exports = res;
res.redirect = function redirect(url) {
  this.format({
    html: function () { var u = escapeHtml(url); return u; }
  });
};
`;
  const f = analyzeFile(src, 'lib/response.js');
  const chain = enclosingAll(f, 6);
  assert.equal(chain[0]!.name, 'html');
  assert.equal(resolvePublic(f, chain[0]!).size, 0);
  assert.deepEqual([...resolvePublic(f, chain[1]!).keys()], ['redirect']);
});

test('a function passed as a callback counts as reachable from the caller', () => {
  const src = `
function baseSet(o, p, v) { o[p] = v; }
function baseZipObject(props, values, assign) { assign({}, props[0], values[0]); }
function zipObjectDeep(props, values) { return baseZipObject(props, values, baseSet); }
lodash.zipObjectDeep = zipObjectDeep;
`;
  const f = analyzeFile(src, 'lodash.js');
  assert.deepEqual([...resolvePublic(f, enclosing(f, 2)!).keys()], ['zipObjectDeep']);
});

test('a named function expression assigned to a variable is known by the variable name', () => {
  const src = `
var parseObject = function (chain, val) { return val; };
var parseKeys = function parseQueryStringKeys(key, val) { return parseObject([key], val); };
module.exports = function (str, opts) { return parseKeys(str, opts); };
`;
  const f = analyzeFile(src, 'lib/parse.js');
  assert.deepEqual([...resolvePublic(f, enclosing(f, 2)!).keys()], ['default']);
});

test('esm exports are public', () => {
  const src = `
export function trim(s) { return s.trim(); }
function helper() { return 1; }
export default function main() { return helper(); }
`;
  const f = analyzeFile(src, 'index.mjs');
  assert.deepEqual([...resolvePublic(f, enclosing(f, 2)!).keys()], ['trim']);
  assert.deepEqual([...resolvePublic(f, enclosing(f, 3)!).keys()], ['default']);
});
