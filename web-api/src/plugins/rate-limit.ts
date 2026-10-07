import type { FastifyInstance } from "fastify";
import rateLimit from "@fastify/rate-limit";

export async function registerRateLimit(app: FastifyInstance) {
  await app.register(rateLimit, {
    max: 100,
    timeWindow: "1 minute",
  });
}

export const authRateLimit = {
  config: {
    rateLimit: {
      max: 10,
      timeWindow: "1 minute",
    },
  },
};
