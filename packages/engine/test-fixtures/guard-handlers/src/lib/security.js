'use strict';
exports.denyAll = () => (req, res) => res.status(401).end();
