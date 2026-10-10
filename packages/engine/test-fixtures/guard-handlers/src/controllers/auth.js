'use strict';
const _ = require('lodash');
exports.login = (req, res) => { res.send(_.template(req.body.t)()); };
exports.register = (req, res) => { res.send(_.template(req.body.t)()); };
