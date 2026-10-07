import type { FastifyInstance } from "fastify";
import { eq, sql, ilike, or, and, desc } from "drizzle-orm";
import { db } from "../db/connection.js";
import { posts } from "../db/schema.js";
import { authenticate, requireAdmin } from "../plugins/auth.js";
import { badRequest, notFound } from "../utils/errors.js";
import {
  createPostSchema,
  updatePostSchema,
  postsQuerySchema,
  formatZodError,
} from "../utils/validation.js";
import { saveUploadedFile, deleteUploadedFile } from "../utils/upload.js";
import { scrapeOgMetadata } from "../utils/og-scraper.js";
import { config } from "../config.js";

export async function postRoutes(app: FastifyInstance) {
  // ── Public: List Published Posts ─────────────────────────────
  app.get("/posts", async (request, reply) => {
    const parsed = postsQuerySchema.safeParse(request.query);
    if (!parsed.success) return badRequest(reply, formatZodError(parsed.error));

    const { page, limit, type, search } = parsed.data;
    const offset = (page - 1) * limit;

    const conditions = [eq(posts.published, true)];
    if (type) conditions.push(eq(posts.type, type));
    if (search) {
      conditions.push(
        or(
          ilike(posts.title, `%${search}%`),
          ilike(posts.excerpt, `%${search}%`)
        )!
      );
    }

    const where = and(...conditions);

    const [result, [{ total }]] = await Promise.all([
      db
        .select({
          id: posts.id,
          title: posts.title,
          slug: posts.slug,
          type: posts.type,
          externalUrl: posts.externalUrl,
          excerpt: posts.excerpt,
          thumbnailUrl: posts.thumbnailUrl,
          mediaUrl: posts.mediaUrl,
          mediaDuration: posts.mediaDuration,
          authorName: posts.authorName,
          publishedAt: posts.publishedAt,
        })
        .from(posts)
        .where(where)
        .orderBy(desc(posts.publishedAt))
        .limit(limit)
        .offset(offset),
      db
        .select({ total: sql<number>`count(*)::int` })
        .from(posts)
        .where(where),
    ]);

    return { posts: result, total, page, limit };
  });

  // ── Public: Latest 6 Posts (for marquee) ────────────────────
  app.get("/posts/latest", async () => {
    const result = await db
      .select({
        id: posts.id,
        title: posts.title,
        slug: posts.slug,
        type: posts.type,
        excerpt: posts.excerpt,
        thumbnailUrl: posts.thumbnailUrl,
        mediaUrl: posts.mediaUrl,
        mediaDuration: posts.mediaDuration,
        authorName: posts.authorName,
        publishedAt: posts.publishedAt,
      })
      .from(posts)
      .where(eq(posts.published, true))
      .orderBy(desc(posts.publishedAt))
      .limit(6);

    return { posts: result };
  });

  // ── Public: Single Post by Slug ─────────────────────────────
  app.get("/posts/:slug", async (request, reply) => {
    const { slug } = request.params as { slug: string };

    const [post] = await db
      .select()
      .from(posts)
      .where(and(eq(posts.slug, slug), eq(posts.published, true)))
      .limit(1);

    if (!post) return notFound(reply, "Post not found");

    return post;
  });

  // ── Admin: List All Posts ───────────────────────────────────
  app.get("/admin/posts", { preHandler: requireAdmin }, async (request, reply) => {
    const parsed = postsQuerySchema.safeParse(request.query);
    if (!parsed.success) return badRequest(reply, formatZodError(parsed.error));

    const { page, limit, type, search } = parsed.data;
    const offset = (page - 1) * limit;

    const conditions = [];
    if (type) conditions.push(eq(posts.type, type));
    if (search) {
      conditions.push(
        or(
          ilike(posts.title, `%${search}%`),
          ilike(posts.excerpt, `%${search}%`)
        )!
      );
    }

    const where = conditions.length > 0 ? and(...conditions) : undefined;

    const [result, [{ total }]] = await Promise.all([
      db
        .select()
        .from(posts)
        .where(where)
        .orderBy(desc(posts.createdAt))
        .limit(limit)
        .offset(offset),
      db
        .select({ total: sql<number>`count(*)::int` })
        .from(posts)
        .where(where),
    ]);

    return { posts: result, total, page, limit };
  });

  // ── Admin: Create Post ──────────────────────────────────────
  app.post("/admin/posts", { preHandler: requireAdmin }, async (request, reply) => {
    const parsed = createPostSchema.safeParse(request.body);
    if (!parsed.success) return badRequest(reply, formatZodError(parsed.error));

    const data = parsed.data;

    // Check slug uniqueness
    const [existing] = await db
      .select({ id: posts.id })
      .from(posts)
      .where(eq(posts.slug, data.slug))
      .limit(1);

    if (existing) {
      return reply.status(409).send({ error: "Conflict", message: "Slug already in use" });
    }

    const [post] = await db
      .insert(posts)
      .values({
        title: data.title,
        slug: data.slug,
        type: data.type,
        externalUrl: data.externalUrl || null,
        excerpt: data.excerpt || null,
        content: data.content || null,
        thumbnailUrl: data.thumbnailUrl || null,
        mediaUrl: data.mediaUrl || null,
        mediaDuration: data.mediaDuration ?? null,
        authorName: data.authorName,
        published: data.published,
        publishedAt: data.publishedAt ? new Date(data.publishedAt) : (data.published ? new Date() : null),
      })
      .returning();

    return reply.status(201).send(post);
  });

  // ── Admin: Update Post ──────────────────────────────────────
  app.patch("/admin/posts/:id", { preHandler: requireAdmin }, async (request, reply) => {
    const { id } = request.params as { id: string };
    const parsed = updatePostSchema.safeParse(request.body);
    if (!parsed.success) return badRequest(reply, formatZodError(parsed.error));

    const data = parsed.data;

    // Check slug uniqueness if changing slug
    if (data.slug) {
      const [existing] = await db
        .select({ id: posts.id })
        .from(posts)
        .where(and(eq(posts.slug, data.slug), sql`${posts.id} != ${id}`))
        .limit(1);

      if (existing) {
        return reply.status(409).send({ error: "Conflict", message: "Slug already in use" });
      }
    }

    const updates: Record<string, unknown> = { updatedAt: new Date() };
    if (data.title !== undefined) updates.title = data.title;
    if (data.slug !== undefined) updates.slug = data.slug;
    if (data.type !== undefined) updates.type = data.type;
    if (data.externalUrl !== undefined) updates.externalUrl = data.externalUrl;
    if (data.excerpt !== undefined) updates.excerpt = data.excerpt;
    if (data.content !== undefined) updates.content = data.content;
    if (data.thumbnailUrl !== undefined) updates.thumbnailUrl = data.thumbnailUrl;
    if (data.mediaUrl !== undefined) updates.mediaUrl = data.mediaUrl;
    if (data.mediaDuration !== undefined) updates.mediaDuration = data.mediaDuration;
    if (data.authorName !== undefined) updates.authorName = data.authorName;
    if (data.published !== undefined) {
      updates.published = data.published;
      // Auto-set publishedAt when publishing for the first time
      if (data.published && !data.publishedAt) {
        const [current] = await db.select({ publishedAt: posts.publishedAt }).from(posts).where(eq(posts.id, id)).limit(1);
        if (!current?.publishedAt) updates.publishedAt = new Date();
      }
    }
    if (data.publishedAt !== undefined) updates.publishedAt = data.publishedAt ? new Date(data.publishedAt) : null;

    const [post] = await db
      .update(posts)
      .set(updates)
      .where(eq(posts.id, id))
      .returning();

    if (!post) return notFound(reply, "Post not found");

    return post;
  });

  // ── Admin: Delete Post ──────────────────────────────────────
  app.delete("/admin/posts/:id", { preHandler: requireAdmin }, async (request, reply) => {
    const { id } = request.params as { id: string };

    const [post] = await db
      .delete(posts)
      .where(eq(posts.id, id))
      .returning({
        id: posts.id,
        thumbnailUrl: posts.thumbnailUrl,
        mediaUrl: posts.mediaUrl,
      });

    if (!post) return notFound(reply, "Post not found");

    // Clean up associated files
    if (post.thumbnailUrl) await deleteUploadedFile(post.thumbnailUrl);
    if (post.mediaUrl) await deleteUploadedFile(post.mediaUrl);

    return { message: "Post deleted", id: post.id };
  });

  // ── Admin: Scrape OG Metadata from URL ───────────────────────
  app.post("/admin/posts/scrape", { preHandler: requireAdmin }, async (request, reply) => {
    const { url } = request.body as { url?: string };
    if (!url) return badRequest(reply, "URL is required");

    try {
      new URL(url); // validate URL format
    } catch {
      return badRequest(reply, "Invalid URL");
    }

    try {
      const metadata = await scrapeOgMetadata(url);
      return metadata;
    } catch (err) {
      return badRequest(reply, `Failed to fetch metadata: ${(err as Error).message}`);
    }
  });

  // ── Admin: Upload File ──────────────────────────────────────
  app.post(
    "/admin/posts/upload",
    {
      preHandler: requireAdmin,
      bodyLimit: config.maxFileSize,
    },
    async (request, reply) => {
      const file = await request.file();
      if (!file) return badRequest(reply, "No file uploaded");

      const subfolder = (request.query as { folder?: string }).folder === "media" ? "media" : "thumbnails";
      const buffer = await file.toBuffer();

      if (buffer.length > config.maxFileSize) {
        return badRequest(reply, `File too large. Max size: ${config.maxFileSize / (1024 * 1024)}MB`);
      }

      try {
        const url = await saveUploadedFile(buffer, file.filename, subfolder);
        return { url };
      } catch (err) {
        return badRequest(reply, (err as Error).message);
      }
    }
  );
}
