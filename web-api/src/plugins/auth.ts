import type { FastifyRequest, FastifyReply } from "fastify";
import { eq } from "drizzle-orm";
import { verifyAccessToken } from "../utils/jwt.js";
import { unauthorized, forbidden } from "../utils/errors.js";
import { db } from "../db/connection.js";
import { users } from "../db/schema.js";

declare module "fastify" {
  interface FastifyRequest {
    userId?: string;
    userRole?: string;
  }
}

export async function authenticate(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const header = request.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return unauthorized(reply, "Missing or invalid authorization header");
  }

  const token = header.slice(7);
  try {
    const payload = verifyAccessToken(token);
    request.userId = payload.sub;
    request.userRole = payload.role;

    // Check if user is suspended
    const [user] = await db
      .select({ status: users.status })
      .from(users)
      .where(eq(users.id, payload.sub))
      .limit(1);

    if (!user || user.status === "suspended") {
      return unauthorized(reply, "Account not found or suspended");
    }
  } catch {
    return unauthorized(reply, "Invalid or expired token");
  }
}

export async function requireAdmin(
  request: FastifyRequest,
  reply: FastifyReply
) {
  await authenticate(request, reply);
  if (reply.sent) return;
  if (request.userRole !== "admin") {
    return forbidden(reply, "Admin access required");
  }
}

export async function optionalAuth(
  request: FastifyRequest,
  _reply: FastifyReply
) {
  const header = request.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) return;

  const token = header.slice(7);
  try {
    const payload = verifyAccessToken(token);
    request.userId = payload.sub;
    request.userRole = payload.role;
  } catch {
    // Silently ignore invalid tokens for optional auth
  }
}
