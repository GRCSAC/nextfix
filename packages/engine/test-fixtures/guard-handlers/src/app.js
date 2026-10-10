'use strict';
const express = require('express');
const _ = require('lodash');
const authController = require('./controllers/auth');
const auth = require('./controllers/auth');
const security = require('./lib/security');
const app = express();
// The final argument is the handler even when its receiver is called "auth".
app.post('/login', authController.login);
app.post('/register', auth.register);
app.get('/x', (req, res) => res.send('x'));
// A named inline handler whose name contains a guard word is still the handler.
app.get('/roles', function getRolePermissions(req, res) { res.send(_.template(req.query.t)()); });
// A final argument that names a guard is the handler and keeps the route guarded.
app.put('/users/:id', security.denyAll());
app.listen(3000);
