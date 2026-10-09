const express = require('express');
const session = require('express-session');
const passport = require('passport');
const flash = require('express-flash');
const _ = require('lodash');
const userController = require('./controllers/user');
const { isLoggedIn } = require('./lib/guards');
const Reports = require('./lib/reports');
const { login, makeHandler } = require('./lib/factories');
const utils = require('./lib/wrap');
const Dao = require('./lib/dao');

const app = express();
const reports = new Reports();
const dao = new Dao();

app.use(session({ secret: 'x' }));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash);

app.get('/', userController.home);
app.post('/login', login());
app.get('/account', passport.authenticate('local'), userController.account);
app.get('/dashboard', isLoggedIn, (req, res) => res.send('ok'));
app.get('/reports', isLoggedIn, reports.list);
app.post('/reports/preview', reports.preview);
app.use('/legacy', userController.legacy);
app.get('/factory', utils.asyncHandler(makeHandler()));
app.get('/nested', (req, res) => {
  dao.load(req.params.id, (err, rows) => {
    res.send(_.template(rows[0])());
  });
});
app.listen(3000);
