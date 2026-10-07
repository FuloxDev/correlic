import type { FastifyInstance } from "fastify";
import { eq } from "drizzle-orm";
import { db } from "../db/connection.js";
import { users } from "../db/schema.js";
import { hashPassword, verifyPassword } from "../utils/hash.js";
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} from "../utils/jwt.js";
import { badRequest, unauthorized, conflict } from "../utils/errors.js";
import { config } from "../config.js";
import { authenticate } from "../plugins/auth.js";
import { registerSchema, loginSchema, formatZodError, verifyEmailDomain } from "../utils/validation.js";
import { authRateLimit } from "../plugins/rate-limit.js";

export async function authRoutes(app: FastifyInstance) {
  // Register
  app.post("/auth/register", authRateLimit, async (request, reply) => {
    const parsed = registerSchema.safeParse(request.body);
    if (!parsed.success) {
      return badRequest(reply, formatZodError(parsed.error));
    }

    const { email, password, name, company, useCase } = parsed.data;

    // Verify email domain is real and not disposable
    const domainError = await verifyEmailDomain(email);
    if (domainError) {
      return badRequest(reply, domainError);
    }

    // Check if email already exists
    const existing = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (existing.length > 0) {
      return conflict(reply, "An account with this email already exists");
    }

    const passwordHash = await hashPassword(password);

    let user: { id: string; role: string };
    try {
      [user] = await db
        .insert(users)
        .values({
          email,
          passwordHash,
          name,
          company: company || null,
          useCase: useCase || null,
        })
        .returning({ id: users.id, role: users.role });
    } catch (err: unknown) {
      // Handle race condition: concurrent registration with same email
      if (err instanceof Error && "code" in err && (err as { code: string }).code === "23505") {
        return conflict(reply, "An account with this email already exists");
      }
      throw err;
    }

    const accessToken = signAccessToken(user.id, user.role);
    const refreshToken = signRefreshToken(user.id, user.role);

    reply.setCookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: config.nodeEnv === "production",
      sameSite: "strict",
      path: "/auth/refresh",
      maxAge: 7 * 24 * 60 * 60, // 7 days
    });

    return reply.status(201).send({
      accessToken,
      user: { id: user.id, email, name, role: user.role },
    });
  });

  // Login
  app.post("/auth/login", authRateLimit, async (request, reply) => {
    const parsed = loginSchema.safeParse(request.body);
    if (!parsed.success) {
      return badRequest(reply, formatZodError(parsed.error));
    }

    const { email, password } = parsed.data;

    const [user] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (!user) {
      // Run bcrypt against a dummy hash to prevent timing attacks
      await verifyPassword(password, "$2b$12$0000000000000000000000000000000000000000000000000000");
      return unauthorized(reply, "Invalid email or password");
    }

    const valid = await verifyPassword(password, user.passwordHash);
    if (!valid) {
      return unauthorized(reply, "Invalid email or password");
    }

    const accessToken = signAccessToken(user.id, user.role);
    const refreshToken = signRefreshToken(user.id, user.role);

    reply.setCookie("refresh_token", refreshToken, {
      httpOnly: true,
      secure: config.nodeEnv === "production",
      sameSite: "strict",
      path: "/auth/refresh",
      maxAge: 7 * 24 * 60 * 60,
    });

    return {
      accessToken,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        status: user.status,
      },
    };
  });

  // Refresh token
  app.post("/auth/refresh", async (request, reply) => {
    const token = request.cookies.refresh_token;
    if (!token) {
      return unauthorized(reply, "No refresh token");
    }

    try {
      const payload = verifyRefreshToken(token);

      // Verify user still exists and is not suspended
      const [user] = await db
        .select({ id: users.id, role: users.role, status: users.status })
        .from(users)
        .where(eq(users.id, payload.sub))
        .limit(1);

      if (!user || user.status === "suspended") {
        return unauthorized(reply, "Account not found or suspended");
      }

      const accessToken = signAccessToken(user.id, user.role);
      const newRefreshToken = signRefreshToken(user.id, user.role);

      reply.setCookie("refresh_token", newRefreshToken, {
        httpOnly: true,
        secure: config.nodeEnv === "production",
        sameSite: "strict",
        path: "/auth/refresh",
        maxAge: 7 * 24 * 60 * 60,
      });

      return { accessToken };
    } catch {
      return unauthorized(reply, "Invalid or expired refresh token");
    }
  });

  // Logout
  app.post(
    "/auth/logout",
    { preHandler: authenticate },
    async (_request, reply) => {
      reply.clearCookie("refresh_token", { path: "/auth/refresh" });
      return { message: "Logged out" };
    }
  );
}
