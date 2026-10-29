import cors from "cors";
import type { Request, Response, NextFunction } from "express";
import { getRequestOrigin } from "./request-origin.js";

const DEV_ORIGINS = ["http://localhost:5173", "http://127.0.0.1:5173"];
const ELECTRON_FILE_ORIGIN = "file://";

function getAllowedOrigins(): string[] {
  const envOrigins = process.env.CORS_ALLOWED_ORIGINS;
  if (!envOrigins) return [];
  return envOrigins
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
}

/**
 * Origins allowed to drive the embedded desktop backend: the desktop app
 * itself and the dev server. Any website open in a browser on the same
 * machine can reach loopback too, so nothing else gets in.
 */
export function isDesktopAppOrigin(origin: string | undefined): boolean {
  if (!origin) return true;
  return (
    DEV_ORIGINS.includes(origin) || origin.startsWith(ELECTRON_FILE_ORIGIN)
  );
}

export function isCorsOriginAllowed(
  req: Request,
  origin: string | undefined,
): boolean {
  if (isDesktopAppOrigin(origin)) return true;

  const configured = getAllowedOrigins();
  if (process.env.ELECTRON_EMBEDDED === "true") {
    return configured.includes(origin) || origin === getRequestOrigin(req);
  }
  if (configured.length === 0) return true;
  if (configured.includes(origin)) return true;

  return origin === getRequestOrigin(req);
}

export function createCorsMiddleware(
  methods: string[] = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  extraHeaders: string[] = [],
) {
  const allowedHeaders = [
    "Origin",
    "X-Requested-With",
    "Content-Type",
    "Accept",
    "Authorization",
    "User-Agent",
    "X-Electron-App",
    "X-Termix-Device-ID",
    "X-Termix-Trust-Token",
    "Cache-Control",
    "x-admin-target-user",
    ...extraHeaders,
  ];

  return (req: Request, res: Response, next: NextFunction) => {
    // Public plugin files have their own credential-free CORS policy. A module
    // imported by Electron's file:// page sends Origin: null, which must stay
    // blocked on authenticated APIs but is safe for these public GETs.
    if (
      (req.method === "GET" || req.method === "HEAD") &&
      req.path.startsWith("/plugin-assets/")
    ) {
      next();
      return;
    }
    const handler = cors({
      origin: (origin, callback) => {
        if (isCorsOriginAllowed(req, origin)) return callback(null, true);
        callback(new Error("Not allowed by CORS"));
      },
      credentials: true,
      methods,
      allowedHeaders,
    });
    handler(req, res, next);
  };
}
