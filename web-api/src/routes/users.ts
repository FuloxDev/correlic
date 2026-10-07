import type { FastifyInstance } from "fastify";
import { eq } from "drizzle-orm";
import { db } from "../db/connection.js";
import { users } from "../db/schema.js";
import { authenticate } from "../plugins/auth.js";
import { notFound, badRequest } from "../utils/errors.js";
import { updateUserSchema, formatZodError } from "../utils/validation.js";

export async function userRoutes(app: FastifyInstance) {
  // Get current user profile
  app.get(
    "/users/me",
    { preHandler: authenticate },
    async (request, reply) => {
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
        })
        .from(users)
        .where(eq(users.id, request.userId!))
        .limit(1);

      if (!user) {
        return notFound(reply, "User not found");
      }

      return user;
    }
  );

  // Update current user profile
  app.patch(
    "/users/me",
    { preHandler: authenticate },
    async (request, reply) => {
      const parsed = updateUserSchema.safeParse(request.body);
      if (!parsed.success) {
        return badRequest(reply, formatZodError(parsed.error));
      }

      const { name, company, useCase } = parsed.data;

      const updates: Record<string, unknown> = { updatedAt: new Date() };
      if (name) updates.name = name;
      if (company !== undefined) updates.company = company;
      if (useCase !== undefined) updates.useCase = useCase;

      const [user] = await db
        .update(users)
        .set(updates)
        .where(eq(users.id, request.userId!))
        .returning({
          id: users.id,
          email: users.email,
          name: users.name,
          company: users.company,
          useCase: users.useCase,
          role: users.role,
          status: users.status,
        });

      return user;
    }
  );
}
