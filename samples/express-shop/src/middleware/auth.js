'use strict';
function requireAuth(req, res, next) {
  if (req.headers['x-session'] === 'demo') return next();
  return res.status(401).json({ error: 'unauthorized' });
}
module.exports = { requireAuth };
