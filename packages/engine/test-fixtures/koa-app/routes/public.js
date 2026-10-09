'use strict';
const Router = require('@koa/router');

const unprotectedRouter = new Router({ prefix: '/public' });
unprotectedRouter.get('/ping', (ctx) => {
  ctx.body = 'pong';
});

module.exports = { unprotectedRouter };
