'use strict';
const express = require('express');
const fp = require('lodash/fp');
const { Parser } = require('xml2js');
const app = express();
class Renderer {
  run(src) { return fp.template(src)(); }
  handle(req, res) { res.send(this.run(req.body.src)); }
}
const renderer = new Renderer();
app.post('/fp', (req, res) => renderer.handle(req, res));
app.post('/xml', (req, res) => { const parser = new Parser({ explicitArray: false }); res.send(parser.parseString(req.body.xml)); });
app.listen(3000);
