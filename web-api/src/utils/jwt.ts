import jwt from "jsonwebtoken";
import { config } from "../config.js";

interface TokenPayload {
  sub: string;
  role: string;
}

export function signAccessToken(userId: string, role: string): string {
  return jwt.sign({ sub: userId, role } satisfies TokenPayload, config.jwtSecret, {
    expiresIn: config.accessTokenExpiry,
  });
}

export function signRefreshToken(userId: string, role: string): string {
  return jwt.sign({ sub: userId, role } satisfies TokenPayload, config.jwtRefreshSecret, {
    expiresIn: config.refreshTokenExpiry,
  });
}

export function verifyAccessToken(token: string): TokenPayload {
  return jwt.verify(token, config.jwtSecret) as TokenPayload;
}

export function verifyRefreshToken(token: string): TokenPayload {
  return jwt.verify(token, config.jwtRefreshSecret) as TokenPayload;
}
