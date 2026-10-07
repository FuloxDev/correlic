import type { FastifyInstance } from "fastify";
import cors from "@fastify/cors";
import { config } from "../config.js";

export async function registerCors(app: FastifyInstance) {
  const origins = [config.corsOrigin];
  // Also allow www variant
  if (config.corsOrigin.includes("://") && !config.corsOrigin.includes("localhost")) {
    const url = new URL(config.corsOrigin);
    if (url.hostname.startsWith("www.")) {
      origins.push(config.corsOrigin.replace("www.", ""));
    } else {
      origins.push(`${url.protocol}//www.${url.hostname}`);
    }
  }

  await app.register(cors, {
    origin: origins,
    credentials: true,
    methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
  });
}
