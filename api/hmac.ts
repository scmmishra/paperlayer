import type { VercelRequest, VercelResponse } from "@vercel/node";

import jwt from "jsonwebtoken";
import crypto from "crypto";

const CHATWOOT_HMAC_SECRET = process.env.CHATWOOT_HMAC_SECRET!;
const AUTH_TOKEN = process.env.AUTH_TOKEN!;

interface JWTData {
  email: string;
}

export default async function generateHMAC(
  req: VercelRequest,
  res: VercelResponse
) {
  try {
    // Verify JWT token
    const token = req.headers.authorization || "";
    const jwtData: JWTData = jwt.verify(token, AUTH_TOKEN) as JWTData;

    // Generate HMAC
    const hmac = crypto
      .createHmac("sha256", CHATWOOT_HMAC_SECRET)
      .update(jwtData.email)
      .digest("hex");

    res.status(200).json({ hmac });
  } catch (err) {
    console.error(err);

    res.status(401).json({ error: "Unauthorized" });
  }
}
