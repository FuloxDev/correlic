import type { FastifyInstance } from "fastify";
import { eq, sql, ilike, or, and, isNull, desc } from "drizzle-orm";
import { db } from "../db/connection.js";
import { users, apiKeys, feedback } from "../db/schema.js";
import { requireAdmin } from "../plugins/auth.js";
import { hashPassword } from "../utils/hash.js";
import { generateApiKey } from "../utils/apikey.js";
import { sendApprovalEmail } from "../utils/email.js";
import { badRequest, notFound, conflict } from "../utils/errors.js";
import {
  adminUpdateUserSchema,
  adminCreateUserSchema,
  adminExtendKeySchema,
  adminQuerySchema,
  formatZodError,
} from "../utils/validation.js";

export async function adminRoutes(app: FastifyInstance) {
  // All admin routes require admin role
  app.addHook("preHandler", requireAdmin);

  // ── Dashboard Stats ──────────────────────────────────────────
  app.get("/admin/stats", async () => {
    const [userStats] = await db
      .select({
        total: sql<number>`count(*)::int`,
        waitlist: sql<number>`count(*) filter (where ${users.status} = 'waitlist')::int`,
        active: sql<number>`count(*) filter (where ${users.status} = 'active')::int`,
        suspended: sql<number>`count(*) filter (where ${users.status} = 'suspended')::int`,
      })
      .from(users);

    const [keyStats] = await db
      .select({
        total: sql<number>`count(*)::int`,
        active: sql<number>`count(*) filter (where ${apiKeys.revokedAt} is null)::int`,
      })
      .from(apiKeys);

    const [feedbackStats] = await db
      .select({
        total: sql<number>`count(*)::int`,
        avgRating: sql<number>`round(avg(${feedback.rating})::numeric, 1)`,
      })
      .from(feedback);

    return {
      users: userStats,
      keys: keyStats,
      feedback: feedbackStats,
    };
  });

  // ── List Users ───────────────────────────────────────────────
  app.get("/admin/users", async (request, reply) => {
    const parsed = adminQuerySchema.safeParse(request.query);
    if (!parsed.success) return badRequest(reply, formatZodError(parsed.error));

    const { page, limit, search, status } = parsed.data;
    const offset = (page - 1) * limit;

    const conditions = [];
    if (status) conditions.push(eq(users.status, status));
    if (search) {
      conditions.push(
        or(
          ilike(users.email, `%${search}%`),
          ilike(users.name, `%${search}%`),
          ilike(users.company, `%${search}%`)
        )!
      );
    }

    const where = conditions.length > 0 ? and(...conditions) : undefined;

    const [result, [{ total }]] = await Promise.all([
      db
        .select({
          id: users.id,
          email: users.email,
          name: users.name,
          company: users.company,
          useCase: users.useCase,
          role: users.role,
          status: users.status,
          createdAt: users.createdAt,
        })
        .from(users)
        .where(where)
        .orderBy(desc(users.createdAt))
        .limit(limit)
        .offset(offset),
      db
        .select({ total: sql<number>`count(*)::int` })
        .from(users)
        .where(where),
    ]);

    return { users: result, total, page, limit };
  });

  // ── Waitlist ─────────────────────────────────────────────────
  app.get("/admin/waitlist", async () => {
    const result = await db
      .select({
        id: users.id,
        email: users.email,
        name: users.name,
        company: users.company,
        useCase: users.useCase,
        createdAt: users.createdAt,
      })
      .from(users)
      .where(eq(users.status, "waitlist"))
      .orderBy(users.createdAt);

    return { users: result };
  });

  // ── Approve User ─────────────────────────────────────────────
  app.patch("/admin/users/:id/approve", async (request, reply) => {
    const { id } = request.params as { id: string };

    const [user] = await db
      .update(users)
      .set({ status: "active", updatedAt: new Date() })
      .where(and(eq(users.id, id), eq(users.status, "waitlist")))
      .returning({ id: users.id, email: users.email, name: users.name, status: users.status });

    if (!user) {
      return notFound(reply, "User not found or not in waitlist");
    }

    // Auto-generate API key for the approved user
    const { plaintext, hash, prefix } = generateApiKey();

    const expiresAt = new Date(Date.now() + 90 * 86_400_000); // 90 days

    const [key] = await db
      .insert(apiKeys)
      .values({
        userId: user.id,
        keyHash: hash,
        keyPrefix: prefix,
        name: "Default",
        expiresAt,
      })
      .returning({
        id: apiKeys.id,
        keyPrefix: apiKeys.keyPrefix,
        expiresAt: apiKeys.expiresAt,
        createdAt: apiKeys.createdAt,
      });

    // Send approval email with API key
    try {
      await sendApprovalEmail(user.email, user.name, plaintext);
    } catch (err) {
      request.log.error(err, "Failed to send approval email");
    }

    return {
      ...user,
      apiKey: plaintext,
      keyId: key.id,
      keyPrefix: key.keyPrefix,
      warning: "API key sent to user via email. This is the only time it will be shown.",
    };
  });

  // ── Get Single User ──────────────────────────────────────────
  app.get("/admin/users/:id", async (request, reply) => {
    const { id } = request.params as { id: string };

    const [user] = await db
      .select({
        id: users.id,
        email: users.email,
        name: users.name,
        company: users.company,
        useCase: users.useCase,
        role: users.role,
        status: users.status,
        createdAt: users.createdAt,
        updatedAt: users.updatedAt,
      })
      .from(users)
      .where(eq(users.id, id))
      .limit(1);

    if (!user) {
      return notFound(reply, "User not found");
    }

    const keys = await db
      .select({
        id: apiKeys.id,
        keyPrefix: apiKeys.keyPrefix,
        name: apiKeys.name,
        lastUsedAt: apiKeys.lastUsedAt,
        revokedAt: apiKeys.revokedAt,
        createdAt: apiKeys.createdAt,
      })
      .from(apiKeys)
      .where(eq(apiKeys.userId, id))
      .orderBy(apiKeys.createdAt);

    return { ...user, keys };
  });

  // ── Update User ──────────────────────────────────────────────
  app.patch("/admin/users/:id", async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = adminUpdateUserSchema.safeParse(request.body);
    if (!parsed.success) {
      return badRequest(reply, formatZodError(parsed.error));
    }

    const data = parsed.data;

    // Check email uniqueness if changing email
    if (data.email) {
      const [existing] = await db
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.email, data.email), sql`${users.id} != ${id}`))
        .limit(1);

      if (existing) {
        return conflict(reply, "Email already in use");
      }
    }

    const updates: Record<string, unknown> = { updatedAt: new Date() };
    if (data.name !== undefined) updates.name = data.name;
    if (data.email !== undefined) updates.email = data.email;
    if (data.company !== undefined) updates.company = data.company;
    if (data.useCase !== undefined) updates.useCase = data.useCase;
    if (data.role !== undefined) updates.role = data.role;
    if (data.status !== undefined) updates.status = data.status;

    const [user] = await db
      .update(users)
      .set(updates)
      .where(eq(users.id, id))
      .returning({
        id: users.id,
        email: users.email,
        name: users.name,
        company: users.company,
        useCase: users.useCase,
        role: users.role,
        status: users.status,
      });

    if (!user) {
      return notFound(reply, "User not found");
    }

    return user;
  });

  // ── Create User ──────────────────────────────────────────────
  app.post("/admin/users", async (request, reply) => {
    const parsed = adminCreateUserSchema.safeParse(request.body);
    if (!parsed.success) {
      return badRequest(reply, formatZodError(parsed.error));
    }

    const { email, password, name, company, useCase, role, status } = parsed.data;

    const [existing] = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (existing) {
      return conflict(reply, "Email already in use");
    }

    const passwordHash = await hashPassword(password);

    const [user] = await db
      .insert(users)
      .values({
        email,
        passwordHash,
        name,
        company: company || null,
        useCase: useCase || null,
        role: role || "user",
        status: status || "active",
      })
      .returning({
        id: users.id,
        email: users.email,
        name: users.name,
        role: users.role,
        status: users.status,
      });

    return reply.status(201).send(user);
  });

  // ── Delete User ──────────────────────────────────────────────
  app.delete("/admin/users/:id", async (request, reply) => {
    const { id } = request.params as { id: string };

    // Prevent deleting yourself
    if (id === request.userId) {
      return badRequest(reply, "Cannot delete your own account");
    }

    const [user] = await db
      .delete(users)
      .where(eq(users.id, id))
      .returning({ id: users.id });

    if (!user) {
      return notFound(reply, "User not found");
    }

    return { message: "User deleted", id: user.id };
  });

  // ── List Feedback ────────────────────────────────────────────
  app.get("/admin/feedback", async (request, reply) => {
    const parsed = adminQuerySchema.safeParse(request.query);
    if (!parsed.success) return { feedback: [], total: 0 };

    const { page, limit } = parsed.data;
    const offset = (page - 1) * limit;

    const [result, [{ total }]] = await Promise.all([
      db
        .select({
          id: feedback.id,
          userId: feedback.userId,
          rating: feedback.rating,
          category: feedback.category,
          subject: feedback.subject,
          message: feedback.message,
          email: feedback.email,
          createdAt: feedback.createdAt,
        })
        .from(feedback)
        .orderBy(desc(feedback.createdAt))
        .limit(limit)
        .offset(offset),
      db
        .select({ total: sql<number>`count(*)::int` })
        .from(feedback),
    ]);

    return { feedback: result, total, page, limit };
  });

  // ── Delete Feedback ──────────────────────────────────────────
  app.delete("/admin/feedback/:id", async (request, reply) => {
    const { id } = request.params as { id: string };

    const [entry] = await db
      .delete(feedback)
      .where(eq(feedback.id, id))
      .returning({ id: feedback.id });

    if (!entry) {
      return notFound(reply, "Feedback not found");
    }

    return { message: "Feedback deleted", id: entry.id };
  });

  // ── List All API Keys ────────────────────────────────────────
  app.get("/admin/keys", async (request, reply) => {
    const parsed = adminQuerySchema.safeParse(request.query);
    if (!parsed.success) return { keys: [], total: 0 };

    const { page, limit } = parsed.data;
    const offset = (page - 1) * limit;

    const [result, [{ total }]] = await Promise.all([
      db
        .select({
          id: apiKeys.id,
          userId: apiKeys.userId,
          userEmail: users.email,
          keyPrefix: apiKeys.keyPrefix,
          name: apiKeys.name,
          lastUsedAt: apiKeys.lastUsedAt,
          revokedAt: apiKeys.revokedAt,
          expiresAt: apiKeys.expiresAt,
          createdAt: apiKeys.createdAt,
        })
        .from(apiKeys)
        .leftJoin(users, eq(apiKeys.userId, users.id))
        .orderBy(desc(apiKeys.createdAt))
        .limit(limit)
        .offset(offset),
      db
        .select({ total: sql<number>`count(*)::int` })
        .from(apiKeys),
    ]);

    return { keys: result, total, page, limit };
  });

  // ── Revoke Any API Key ───────────────────────────────────────
  app.delete("/admin/keys/:id", async (request, reply) => {
    const { id } = request.params as { id: string };

    const [key] = await db
      .update(apiKeys)
      .set({ revokedAt: new Date() })
      .where(and(eq(apiKeys.id, id), isNull(apiKeys.revokedAt)))
      .returning({ id: apiKeys.id });

    if (!key) {
      return notFound(reply, "API key not found or already revoked");
    }

    return { message: "API key revoked", id: key.id };
  });

  // ── Extend API Key Expiry ────────────────────────────────────
  app.patch("/admin/keys/:id/extend", async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = adminExtendKeySchema.safeParse(request.body);
    if (!parsed.success) {
      return badRequest(reply, formatZodError(parsed.error));
    }

    const { extendDays } = parsed.data;
    const newExpiresAt = new Date(Date.now() + extendDays * 86_400_000);

    const [key] = await db
      .update(apiKeys)
      .set({ expiresAt: newExpiresAt })
      .where(and(eq(apiKeys.id, id), isNull(apiKeys.revokedAt)))
      .returning({
        id: apiKeys.id,
        expiresAt: apiKeys.expiresAt,
      });

    if (!key) {
      return notFound(reply, "API key not found or revoked");
    }

    return { message: "Key expiry extended", id: key.id, expiresAt: key.expiresAt };
  });
}
