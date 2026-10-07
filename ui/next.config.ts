import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Standalone output for Docker deployment
  output: 'standalone',
  // Extra dev origins can be added with NEXT_ALLOWED_DEV_ORIGINS=https://host1,https://host2
  allowedDevOrigins: (process.env.NEXT_ALLOWED_DEV_ORIGINS || '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean),
};

export default nextConfig;

