const _ = require('lodash');
class Reports {
  list(req, res) { res.json(this.render([])); }
  preview(req, res) { res.send(this.render(req.body.rows)); }
  render(rows) { return _.template('<%= rows %>')({ rows }); }
}
module.exports = Reports;
