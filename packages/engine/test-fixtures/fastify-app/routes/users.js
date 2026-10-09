'use strict';
const _ = require('lodash');

module.exports = async function usersRoutes(fastify, opts) {
  fastify.get('/', async () => []);
  fastify.post('/:id/rename', async (request) => {
    const name = _.trim(request.body.name);
    return { name };
  });
};
