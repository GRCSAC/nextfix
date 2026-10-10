import express from 'express';
import { render } from './render.js';
const app = express();
app.post('/p', (req, res) => { res.send(render(req.body.src)); });
app.listen(3000);
