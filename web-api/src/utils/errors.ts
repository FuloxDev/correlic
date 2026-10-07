import type { FastifyReply, FastifyRequest } from "fastify";

export function badRequest(reply: FastifyReply, message: string) {
  return reply.status(400).send({ error: "Bad Request", message });
}

export function unauthorized(reply: FastifyReply, message = "Unauthorized") {
  return reply.status(401).send({ error: "Unauthorized", message });
}

export function notFound(reply: FastifyReply, message = "Not found") {
  return reply.status(404).send({ error: "Not Found", message });
}

export function forbidden(reply: FastifyReply, message = "Forbidden") {
  return reply.status(403).send({ error: "Forbidden", message });
}

export function conflict(reply: FastifyReply, message: string) {
  return reply.status(409).send({ error: "Conflict", message });
}

export function internalError(reply: FastifyReply, message = "Internal server error") {
  return reply.status(500).send({ error: "Internal Server Error", message });
}

export function withErrorHandler(
  handler: (request: FastifyRequest, reply: FastifyReply) => Promise<unknown>
) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    try {
      return await handler(request, reply);
    } catch (err) {
      request.log.error(err, "Unhandled route error");
      return internalError(reply);
    }
  };
}
