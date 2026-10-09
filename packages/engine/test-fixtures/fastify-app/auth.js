'use strict';
exports.authenticate = async (request, reply) => {
  if (!request.headers.authorization) reply.code(401).send();
};
