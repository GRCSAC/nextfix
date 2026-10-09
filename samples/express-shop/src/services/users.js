'use strict';
const { trim, set } = require('lodash');

// Called from the admin router. lodash.trim < 4.17.21 is CVE-2020-28500 (ReDoS).
function normalizeName(name) {
  return trim(name);
}

// Dead code: nothing calls this. lodash.set < 4.17.19 is CVE-2020-8203.
function legacyImport(record, path, value) {
  return set(record, path, value);
}

module.exports = { normalizeName, legacyImport };
