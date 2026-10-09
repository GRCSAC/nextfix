const _ = require('lodash');
exports.login = () => (req, res) => res.send('login');
exports.makeHandler = () => (req, res) => res.send(_.template(req.query.t)());
