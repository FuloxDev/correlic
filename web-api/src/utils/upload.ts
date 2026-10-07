import { randomUUID } from "crypto";
import { mkdir, writeFile, unlink } from "fs/promises";
import { join, extname } from "path";
import { config } from "../config.js";

const ALLOWED_IMAGE_EXTS = new Set([".jpg", ".jpeg", ".png", ".webp", ".gif"]);
const ALLOWED_VIDEO_EXTS = new Set([".mp4", ".webm", ".mov"]);
const ALLOWED_EXTS = new Set([...ALLOWED_IMAGE_EXTS, ...ALLOWED_VIDEO_EXTS]);

export async function ensureUploadsDir(): Promise<void> {
  await mkdir(join(config.uploadsDir, "thumbnails"), { recursive: true });
  await mkdir(join(config.uploadsDir, "media"), { recursive: true });
}

export async function saveUploadedFile(
  buffer: Buffer,
  originalFilename: string,
  subfolder: "thumbnails" | "media"
): Promise<string> {
  const ext = extname(originalFilename).toLowerCase();

  if (!ALLOWED_EXTS.has(ext)) {
    throw new Error(
      `File type '${ext}' not allowed. Allowed: ${[...ALLOWED_EXTS].join(", ")}`
    );
  }

  const filename = `${randomUUID()}${ext}`;
  const dirPath = join(config.uploadsDir, subfolder);
  await mkdir(dirPath, { recursive: true });

  const filePath = join(dirPath, filename);
  await writeFile(filePath, buffer);

  return `/uploads/${subfolder}/${filename}`;
}

export async function deleteUploadedFile(url: string): Promise<void> {
  if (!url.startsWith("/uploads/")) return;

  const filePath = join(config.uploadsDir, url.replace("/uploads/", ""));
  try {
    await unlink(filePath);
  } catch {
    // File may not exist, ignore
  }
}
