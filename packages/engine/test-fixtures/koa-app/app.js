'use strict';
const Koa = require('koa');
const Router = require('@koa/router');
const _ = require('lodash');
const requireAuth = require('./auth');
const adminRouter = require('./routes/admin');
const { unprotectedRouter } = require('./routes/public');

const app = new Koa();
const router = new Router({ prefix: '/api' });

router.get('/health', (ctx) => {
  ctx.body = { ok: true };
});

router.post('/preview', async (ctx) => {
  ctx.body = _.template(ctx.request.body.template)();
});

router.get('search', '/search', requireAuth, (ctx) => {
  ctx.body = _.trim(ctx.query.q);
});

app.use(unprotectedRouter.routes());
app.use(router.routes());
app.use(router.allowedMethods());
app.use(adminRouter.routes());
app.listen(3000);
