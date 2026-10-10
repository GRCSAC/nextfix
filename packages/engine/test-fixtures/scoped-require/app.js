'use strict';
const express = require('express');
const app = express();
// require() inside the handler: the package is imported and the call resolves through the binding.
app.post('/p', (req, res) => { const _ = require('lodash'); res.send(_.template(req.body.src)()); });
// Dynamic import() of a sub-path, destructured.
app.post('/q', async (req, res) => { const { default: t } = await import('lodash/template'); res.send(t(req.body.src)()); });
app.listen(3000);
