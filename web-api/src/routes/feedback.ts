import type { FastifyInstance } from "fastify";
import { db } from "../db/connection.js";
import { feedback } from "../db/schema.js";
import { optionalAuth } from "../plugins/auth.js";
import { badRequest } from "../utils/errors.js";
import { feedbackSchema, formatZodError } from "../utils/validation.js";

export async function feedbackRoutes(app: FastifyInstance) {
  app.post(
    "/feedback",
    {
      preHandler: optionalAuth,
      config: { rateLimit: { max: 5, timeWindow: "1 minute" } },
    },
    async (request, reply) => {
      const parsed = feedbackSchema.safeParse(request.body);
      if (!parsed.success) {
        return badRequest(reply, formatZodError(parsed.error));
      }

      const { rating, category, subject, message, email } = parsed.data;

      const [entry] = await db
        .insert(feedback)
        .values({
          userId: request.userId || null,
          rating,
          category,
          subject,
          message,
          email: email || null,
        })
        .returning({ id: feedback.id, createdAt: feedback.createdAt });

      return reply.status(201).send({
        message: "Feedback received — thanks!",
        id: entry.id,
      });
    }
  );
}
