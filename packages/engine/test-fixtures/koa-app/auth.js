'use strict';
module.exports = async function requireAuth(ctx, next) {
  if (!ctx.state.user) ctx.throw(401);
  await next();
};
