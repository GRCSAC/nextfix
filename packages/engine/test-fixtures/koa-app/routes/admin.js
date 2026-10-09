'use strict';
const Router = require('@koa/router');
const _ = require('lodash');
const requireAuth = require('../auth');

const router = new Router();
router.prefix('/admin');
router.use(requireAuth);

router.post('/layout', (ctx) => {
  ctx.body = _.template(ctx.request.body.layout)();
});

module.exports = router;
