import dotenv from "dotenv";
dotenv.config();

function required(key: string): string {
  const value = process.env[key];
  if (!value) throw new Error(`Missing required env var: ${key}`);
  return value;
}

function requiredMinLength(key: string, min: number): string {
  const value = required(key);
  if (value.length < min) {
    throw new Error(`${key} must be at least ${min} characters`);
  }
  return value;
}

export const config = {
  port: parseInt(process.env.PORT || "3001", 10),
  nodeEnv: process.env.NODE_ENV || "development",
  databaseUrl: required("DATABASE_URL"),
  jwtSecret: requiredMinLength("JWT_SECRET", 32),
  jwtRefreshSecret: requiredMinLength("JWT_REFRESH_SECRET", 32),
  corsOrigin: process.env.CORS_ORIGIN || "http://localhost:3000",
  accessTokenExpiry: "7d",
  refreshTokenExpiry: "7d",
  smtpHost: process.env.SMTP_HOST || "",
  smtpPort: parseInt(process.env.SMTP_PORT || "465", 10),
  smtpUser: process.env.SMTP_USER || "",
  smtpPass: process.env.SMTP_PASS || "",
  emailFrom: process.env.EMAIL_FROM || "hello@correlic.com",
  uploadsDir: process.env.UPLOADS_DIR || "./uploads",
  maxFileSize: 500 * 1024 * 1024, // 500MB for videos
} as const;
