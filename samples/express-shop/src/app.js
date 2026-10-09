'use strict';
// Demo target for NextFix. Intentionally depends on old versions.
const express = require('express');
const { requireAuth } = require('./middleware/auth');
const render = require('./services/render');
const adminRouter = require('./routes/admin');

const app = express();
app.use(express.json());

// Unauthenticated: user-controlled template source reaches lodash.template (CVE-2021-23337).
app.post('/preview', (req, res) => {
  const html = render.renderTemplate(req.body.template, req.body.data);
  res.type('html').send(html);
});

// Unauthenticated: user-controlled redirect target (CVE-2024-29041, CVE-2024-43796).
app.get('/go', (req, res) => {
  res.redirect(req.query.to);
});

// Health check: no third-party calls at all.
app.get('/healthz', (req, res) => {
  res.json({ ok: true });
});

// Everything under /admin requires a session.
app.use('/admin', requireAuth, adminRouter);

const port = process.env.PORT || 3000;
app.listen(port, () => console.log('express-shop listening on ' + port));
