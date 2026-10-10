'use strict';
const express = require('express');
const _ = require('lodash');
const app = express();
// A bare throw is validation, not a guard.
app.use((req, res, next) => { if (!req.headers['content-type']) throw new Error('bad request'); next(); });
// Inline middleware that answers 401 guards every route registered after it.
app.use((req, res, next) => { if (!req.headers.authorization) return res.status(401).send('no'); next(); });
// The final argument of a scoped use() is a handler even when it can reject.
app.use('/files', (req, res) => { if (req.path.includes('..')) return res.status(403).end(); res.send('file'); });
app.post('/p', (req, res) => res.send(_.template(req.body.src)()));
app.listen(3000);
