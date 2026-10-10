'use strict';
const express = require('express');
const _ = require('lodash');
const app = express();
// A closure defined in the handler and called by name captures a request-derived local.
app.post('/p', (req, res) => { const data = req.body.src; const inner = () => _.template(data)(); res.send(inner()); });
// A callback passed elsewhere captures the same kind of local.
app.post('/q', (req, res) => { const data = req.body.src; setTimeout(() => res.send(_.template(data)()), 0); });
app.listen(3000);
