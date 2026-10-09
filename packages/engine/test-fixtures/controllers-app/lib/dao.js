function Dao() {
  this.load = (id, cb) => cb(null, [id]);
}
module.exports = Dao;
