import express from 'express';
import template from 'lodash/template';
const app = express();
app.post('/t', (req, res) => { res.send(template(req.body.src)()); });
app.listen(3000);
