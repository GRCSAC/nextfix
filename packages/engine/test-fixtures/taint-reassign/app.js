'use strict';
const express = require('express');
const _ = require('lodash');
const app = express();
// Reassigning a parameter to a value derived from itself keeps it as request data.
function render(src) { src = src.trim(); return _.template(src)(); }
app.post('/p', (req, res) => res.send(render(req.body.src)));
app.listen(3000);
