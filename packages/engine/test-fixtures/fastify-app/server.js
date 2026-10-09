'use strict';
const fastify = require('fastify')({ logger: true });
const _ = require('lodash');
const { authenticate } = require('./auth');

fastify.get('/health', async () => ({ ok: true }));

// Route options with a preHandler guard.
fastify.get('/admin/report', { preHandler: [authenticate] }, async (request, reply) => {
  return _.template(request.query.layout)({ rows: [] });
});

// fastify.route() with a handler property, no auth.
fastify.route({
  method: 'POST',
  url: '/preview',
  handler: async (request, reply) => reply.send(_.template(request.body.template)()),
});

// Plugin in another file, mounted with a prefix.
fastify.register(require('./routes/users'), { prefix: '/users' });

// Plugin defined here, registered with a prefix and a scoped onRequest guard.
async function billing(instance) {
  instance.addHook('onRequest', authenticate);
  instance.post('/invoice', async (request) => _.template(request.body.layout)());
}
fastify.register(billing, { prefix: '/billing' });

fastify.listen({ port: 3000 });
