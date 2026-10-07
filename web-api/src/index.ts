import { resolve } from "path";
import Fastify from "fastify";
import cookie from "@fastify/cookie";
import fastifyMultipart from "@fastify/multipart";
import fastifyStatic from "@fastify/static";
import { config } from "./config.js";
import { registerCors } from "./plugins/cors.js";
import { registerRateLimit } from "./plugins/rate-limit.js";
import { authRoutes } from "./routes/auth.js";
import { userRoutes } from "./routes/users.js";
import { keyRoutes } from "./routes/keys.js";
import { feedbackRoutes } from "./routes/feedback.js";
import { adminRoutes } from "./routes/admin.js";
import { postRoutes } from "./routes/posts.js";
import { ensureUploadsDir } from "./utils/upload.js";

const app = Fastify({
  logger: {
    level: config.nodeEnv === "production" ? "info" : "debug",
  },
  bodyLimit: 92_428_800, // 50MB — covers video uploads; multipart plugin enforces per-file limits
});

// Ensure uploads directory exists
await ensureUploadsDir();

// Plugins
await app.register(cookie);
await app.register(fastifyMultipart, {
  limits: { fileSize: config.maxFileSize },
});
await app.register(fastifyStatic, {
  root: resolve(config.uploadsDir),
  prefix: "/uploads/",
  decorateReply: false,
});
await registerCors(app);
await registerRateLimit(app);

// Routes
await app.register(authRoutes);
await app.register(userRoutes);
await app.register(keyRoutes);
await app.register(feedbackRoutes);
await app.register(adminRoutes);
await app.register(postRoutes);

// Global error handler
app.setErrorHandler((error, request, reply) => {
  request.log.error(error, "Unhandled error");
  reply.status(500).send({ error: "Internal Server Error", message: "Something went wrong" });
});

// Health check
app.get("/health", async () => ({ status: "ok", timestamp: new Date().toISOString() }));

// Start
try {
  await app.listen({ port: config.port, host: "0.0.0.0" });
  app.log.info(`Correlic API running on port ${config.port}`);
} catch (err) {
  app.log.error(err);
  process.exit(1);
}
