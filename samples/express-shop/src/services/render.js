'use strict';
const _ = require('lodash');

// Compiles a user-supplied template. lodash.template < 4.17.21 is CVE-2021-23337.
function renderTemplate(source, data) {
  const compiled = _.template(source);
  return compiled(data || {});
}

module.exports = { renderTemplate };
