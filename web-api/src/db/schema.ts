import {
  pgTable,
  uuid,
  varchar,
  text,
  integer,
  boolean,
  timestamp,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";

export const users = pgTable("users", {
  id: uuid("id").defaultRandom().primaryKey(),
  email: varchar("email", { length: 255 }).notNull().unique(),
  passwordHash: varchar("password_hash", { length: 255 }).notNull(),
  name: varchar("name", { length: 255 }).notNull(),
  company: varchar("company", { length: 255 }),
  useCase: varchar("use_case", { length: 100 }),
  role: varchar("role", { length: 20 }).notNull().default("user"),
  status: varchar("status", { length: 20 }).notNull().default("waitlist"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const apiKeys = pgTable("api_keys", {
  id: uuid("id").defaultRandom().primaryKey(),
  userId: uuid("user_id")
    .notNull()
    .references(() => users.id, { onDelete: "cascade" }),
  keyHash: varchar("key_hash", { length: 255 }).notNull(),
  keyPrefix: varchar("key_prefix", { length: 12 }).notNull(),
  name: varchar("name", { length: 100 }).notNull().default("Default"),
  lastUsedAt: timestamp("last_used_at"),
  revokedAt: timestamp("revoked_at"),
  expiresAt: timestamp("expires_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => [
  index("idx_api_keys_user_id").on(table.userId),
  index("idx_api_keys_key_hash").on(table.keyHash),
]);

export const feedback = pgTable("feedback", {
  id: uuid("id").defaultRandom().primaryKey(),
  userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
  rating: integer("rating").notNull(),
  category: varchar("category", { length: 50 }).notNull(),
  subject: varchar("subject", { length: 255 }).notNull(),
  message: text("message").notNull(),
  email: varchar("email", { length: 255 }),
  createdAt: timestamp("created_at").notNull().defaultNow(),
}, (table) => [
  index("idx_feedback_user_id").on(table.userId),
]);

export const posts = pgTable("posts", {
  id: uuid("id").defaultRandom().primaryKey(),
  title: varchar("title", { length: 255 }).notNull(),
  slug: varchar("slug", { length: 255 }).notNull(),
  type: varchar("type", { length: 20 }).notNull(), // video | article
  externalUrl: varchar("external_url", { length: 500 }), // for articles linked from Hashnode etc.
  excerpt: varchar("excerpt", { length: 500 }),
  content: text("content"),
  thumbnailUrl: varchar("thumbnail_url", { length: 500 }),
  mediaUrl: varchar("media_url", { length: 500 }),
  mediaDuration: integer("media_duration"), // seconds, for videos
  authorName: varchar("author_name", { length: 255 }).notNull(),
  published: boolean("published").notNull().default(false),
  publishedAt: timestamp("published_at"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
}, (table) => [
  uniqueIndex("idx_posts_slug").on(table.slug),
  index("idx_posts_type").on(table.type),
  index("idx_posts_published").on(table.published),
  index("idx_posts_published_at").on(table.publishedAt),
]);
