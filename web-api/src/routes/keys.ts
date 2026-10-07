import type { FastifyInstance, FastifyRequest, FastifyReply } from "fastify";
import { eq, and, isNull } from "drizzle-orm";
import { db } from "../db/connection.js";
import { apiKeys, users } from "../db/schema.js";
import { authenticate } from "../plugins/auth.js";
import { generateApiKey, hashApiKey } from "../utils/apikey.js";
import { badRequest, notFound, unauthorized } from "../utils/errors.js";
import { createKeySchema, formatZodError } from "../utils/validation.js";

export async function keyRoutes(app: FastifyInstance) {
  // List API keys (no plaintext, just metadata)
  app.get("/keys", { preHandler: authenticate }, async (request) => {
    const keys = await db
      .select({
        id: apiKeys.id,
        keyPrefix: apiKeys.keyPrefix,
        name: apiKeys.name,
        lastUsedAt: apiKeys.lastUsedAt,
        revokedAt: apiKeys.revokedAt,
        expiresAt: apiKeys.expiresAt,
        createdAt: apiKeys.createdAt,
      })
      .from(apiKeys)
      .where(eq(apiKeys.userId, request.userId!))
      .orderBy(apiKeys.createdAt);

    return { keys };
  });

  // Create new API key
  app.post("/keys", { preHandler: authenticate }, async (request, reply) => {
    const parsed = createKeySchema.safeParse(request.body || {});
    if (!parsed.success) {
      return badRequest(reply, formatZodError(parsed.error));
    }

    const { name, expiresInDays } = parsed.data;
    const { plaintext, hash, prefix } = generateApiKey();
    const days = expiresInDays ?? 90;
    const expiresAt = new Date(Date.now() + days * 86_400_000);

    const [key] = await db
      .insert(apiKeys)
      .values({
        userId: request.userId!,
        keyHash: hash,
        keyPrefix: prefix,
        name: name || "Default",
        expiresAt,
      })
      .returning({
        id: apiKeys.id,
        keyPrefix: apiKeys.keyPrefix,
        name: apiKeys.name,
        expiresAt: apiKeys.expiresAt,
        createdAt: apiKeys.createdAt,
      });

    // Return plaintext ONCE — it will never be shown again
    return reply.status(201).send({
      ...key,
      key: plaintext,
      warning: "Save this key now. It will not be shown again.",
    });
  });

  // Revoke an API key
  app.delete(
    "/keys/:id",
    { preHandler: authenticate },
    async (request, reply) => {
      const { id } = request.params as { id: string };

      const [key] = await db
        .update(apiKeys)
        .set({ revokedAt: new Date() })
        .where(
          and(
            eq(apiKeys.id, id),
            eq(apiKeys.userId, request.userId!),
            isNull(apiKeys.revokedAt)
          )
        )
        .returning({ id: apiKeys.id });

      if (!key) {
        return notFound(reply, "API key not found or already revoked");
      }

      return { message: "API key revoked", id: key.id };
    }
  );

  // Regenerate: revoke all existing keys and create a fresh one
  app.post(
    "/keys/regenerate",
    { preHandler: authenticate },
    async (request, reply) => {
      // Revoke all active keys for this user
      await db
        .update(apiKeys)
        .set({ revokedAt: new Date() })
        .where(
          and(eq(apiKeys.userId, request.userId!), isNull(apiKeys.revokedAt))
        );

      // Create a new key
      const { plaintext, hash, prefix } = generateApiKey();
      const expiresAt = new Date(Date.now() + 90 * 86_400_000);

      await db.insert(apiKeys).values({
        userId: request.userId!,
        keyHash: hash,
        keyPrefix: prefix,
        name: "Default",
        expiresAt,
      });

      // Return updated key list
      const keys = await db
        .select({
          id: apiKeys.id,
          keyPrefix: apiKeys.keyPrefix,
          name: apiKeys.name,
          lastUsedAt: apiKeys.lastUsedAt,
          revokedAt: apiKeys.revokedAt,
          expiresAt: apiKeys.expiresAt,
          createdAt: apiKeys.createdAt,
        })
        .from(apiKeys)
        .where(eq(apiKeys.userId, request.userId!))
        .orderBy(apiKeys.createdAt);

      return { apiKey: plaintext, keys };
    }
  );

  // Verify an API key (called by the agent, dashboard, and backend)
  // Key comes from headers (x-api-key or Authorization), not the body
  const verifyOpts = {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: "1 minute",
      },
    },
  };

  const verifyHandler = async (request: FastifyRequest, reply: FastifyReply) => {
      const apiKeyHeader =
        request.headers["x-api-key"] ||
        request.headers["authorization"]?.replace("Bearer ", "");

      if (!apiKeyHeader || typeof apiKeyHeader !== "string") {
        return unauthorized(reply, "Missing API key");
      }

      const hash = hashApiKey(apiKeyHeader);

      const [key] = await db
        .select({
          id: apiKeys.id,
          userId: apiKeys.userId,
          revokedAt: apiKeys.revokedAt,
          expiresAt: apiKeys.expiresAt,
        })
        .from(apiKeys)
        .where(eq(apiKeys.keyHash, hash))
        .limit(1);

      if (!key || key.revokedAt) {
        return unauthorized(reply, "Invalid or revoked API key");
      }

      // Check expiry
      if (key.expiresAt && key.expiresAt < new Date()) {
        return reply.status(401).send({
          error: "Unauthorized",
          message: "API key expired",
          code: "KEY_EXPIRED",
        });
      }

      // Check user status
      const [user] = await db
        .select({ status: users.status })
        .from(users)
        .where(eq(users.id, key.userId))
        .limit(1);

      if (!user || user.status === "suspended") {
        return unauthorized(reply, "Account suspended");
      }

      // Update last used timestamp
      await db
        .update(apiKeys)
        .set({ lastUsedAt: new Date() })
        .where(eq(apiKeys.id, key.id));

      return {
        valid: true,
        userId: key.userId,
        expiresAt: key.expiresAt?.toISOString() || null,
      };
  };

  // Register for both POST and GET (POST for backward compat, GET for simple header-only calls)
  app.post("/keys/verify", verifyOpts, verifyHandler);
  app.get("/keys/verify", verifyOpts, verifyHandler);
}
