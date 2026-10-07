import { z } from "zod";
import dns from "dns/promises";

// Domains known to accept any address or commonly used for fake signups
const BLOCKED_EMAIL_DOMAINS = new Set([
  "test.com",
  "example.com",
  "example.org",
  "example.net",
  "mailinator.com",
  "guerrillamail.com",
  "guerrillamail.de",
  "tempmail.com",
  "throwaway.email",
  "yopmail.com",
  "sharklasers.com",
  "guerrillamailblock.com",
  "grr.la",
  "dispostable.com",
  "trashmail.com",
  "fakeinbox.com",
  "maildrop.cc",
  "temp-mail.org",
  "getnada.com",
  "10minutemail.com",
  "mailnesia.com",
  "tempail.com",
  "tempr.email",
  "discard.email",
  "mailcatch.com",
  "trash-mail.com",
  "mytemp.email",
  "mohmal.com",
  "burnermail.io",
  "harakirimail.com",
  "tmail.ws",
  "emailondeck.com",
  "crazymailing.com",
  "mailnator.com",
  "spamgourmet.com",
  "nomail.com",
  "noemail.com",
  "nobody.com",
  "invalid.com",
  "localhost",
]);

/** Check that the email domain is not blocked and has valid MX records. */
export async function verifyEmailDomain(email: string): Promise<string | null> {
  const domain = email.split("@")[1];
  if (!domain) return "Invalid email format";

  if (BLOCKED_EMAIL_DOMAINS.has(domain.toLowerCase())) {
    return "Please use a valid work or personal email address";
  }

  try {
    const mx = await dns.resolveMx(domain);
    if (!mx || mx.length === 0) {
      return "This email domain does not accept mail";
    }
  } catch {
    return "This email domain does not appear to be valid";
  }

  return null; // all good
}

const emailSchema = z
  .string()
  .email("Invalid email format")
  .max(255, "Email must be 255 characters or less")
  .transform((e) => e.toLowerCase());

const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(128, "Password must be 128 characters or less")
  .regex(/[A-Z]/, "Password must contain at least one uppercase letter")
  .regex(/[0-9]/, "Password must contain at least one number")
  .regex(
    /[^A-Za-z0-9]/,
    "Password must contain at least one special character"
  );

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  name: z.string().trim().min(1, "Name is required").max(100, "Name too long"),
  company: z.string().max(200, "Company name too long").optional(),
  useCase: z.string().max(100, "Use case too long").optional(),
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, "Password is required"),
});

export const updateUserSchema = z
  .object({
    name: z.string().min(1, "Name cannot be empty").max(100, "Name too long").optional(),
    company: z.string().max(200, "Company name too long").nullish(),
    useCase: z.string().max(100, "Use case too long").nullish(),
  })
  .refine(
    (data) =>
      data.name !== undefined ||
      data.company !== undefined ||
      data.useCase !== undefined,
    { message: "No fields to update" }
  );

const validCategories = ["bug", "feature", "detection", "ux", "other"] as const;

export const feedbackSchema = z.object({
  rating: z.number().int().min(1, "Rating must be at least 1").max(5, "Rating must be at most 5"),
  category: z.enum(validCategories, {
    message: "Category must be one of: bug, feature, detection, ux, other",
  }),
  subject: z.string().min(1, "Subject is required").max(255, "Subject too long"),
  message: z.string().min(1, "Message is required").max(5000, "Message too long"),
  email: emailSchema.optional(),
});

export const createKeySchema = z.object({
  name: z.string().max(100, "Key name too long").optional(),
  expiresInDays: z.coerce.number().int().min(1).max(365).optional(),
});

export const adminExtendKeySchema = z.object({
  extendDays: z.coerce.number().int().min(1).max(365),
});

const validRoles = ["user", "admin"] as const;
const validStatuses = ["waitlist", "active", "suspended"] as const;

export const adminUpdateUserSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  email: emailSchema.optional(),
  company: z.string().max(200).nullish(),
  useCase: z.string().max(100).nullish(),
  role: z.enum(validRoles).optional(),
  status: z.enum(validStatuses).optional(),
});

export const adminCreateUserSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  name: z.string().trim().min(1, "Name is required").max(100, "Name too long"),
  company: z.string().max(200).optional(),
  useCase: z.string().max(100).optional(),
  role: z.enum(validRoles).optional(),
  status: z.enum(validStatuses).optional(),
});

export const adminQuerySchema = z.object({
  page: z.coerce.number().int().min(1).optional().default(1),
  limit: z.coerce.number().int().min(1).max(100).optional().default(20),
  search: z.string().max(255).optional(),
  status: z.enum(validStatuses).optional(),
});

// ── Posts ──────────────────────────────────────────────────────

const validPostTypes = ["video", "article"] as const;

const slugRegex = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

export const createPostSchema = z.object({
  title: z.string().min(1, "Title is required").max(255, "Title too long"),
  slug: z
    .string()
    .min(1, "Slug is required")
    .max(255, "Slug too long")
    .regex(slugRegex, "Slug must be lowercase alphanumeric with hyphens"),
  type: z.enum(validPostTypes, {
    message: "Type must be one of: video, article",
  }),
  externalUrl: z.string().url().max(500).optional(),
  excerpt: z.string().max(500, "Excerpt too long").optional(),
  content: z.string().max(50000, "Content too long").optional(),
  thumbnailUrl: z.string().max(500).optional(),
  mediaUrl: z.string().max(500).optional(),
  mediaDuration: z.number().int().min(0).optional(),
  authorName: z.string().min(1, "Author name is required").max(255),
  published: z.boolean().optional().default(false),
  publishedAt: z.string().datetime().optional(),
});

export const updatePostSchema = z
  .object({
    title: z.string().min(1).max(255).optional(),
    slug: z.string().min(1).max(255).regex(slugRegex).optional(),
    type: z.enum(validPostTypes).optional(),
    externalUrl: z.string().url().max(500).nullish(),
    excerpt: z.string().max(500).nullish(),
    content: z.string().max(50000).nullish(),
    thumbnailUrl: z.string().max(500).nullish(),
    mediaUrl: z.string().max(500).nullish(),
    mediaDuration: z.number().int().min(0).nullish(),
    authorName: z.string().min(1).max(255).optional(),
    published: z.boolean().optional(),
    publishedAt: z.string().datetime().nullish(),
  })
  .refine(
    (data) => Object.values(data).some((v) => v !== undefined),
    { message: "No fields to update" }
  );

export const postsQuerySchema = z.object({
  page: z.coerce.number().int().min(1).optional().default(1),
  limit: z.coerce.number().int().min(1).max(50).optional().default(12),
  type: z.enum(validPostTypes).optional(),
  search: z.string().max(255).optional(),
});

export function formatZodError(error: z.ZodError): string {
  return error.issues.map((e) => e.message).join(", ");
}
