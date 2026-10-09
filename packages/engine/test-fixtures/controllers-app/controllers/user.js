const _ = require('lodash');
exports.home = (req, res) => res.send('home');
exports.account = (req, res) => res.json(_.pick(req.user, ['name']));
exports.legacy = (req, res) => res.send(_.template(req.query.t)());
