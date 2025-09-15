import crypto from "crypto";

const API_KEY = process.env.API_KEY; // define en Vercel

export default function handler(req, res) {
  // Verificar header
  const auth = req.headers['authorization'];
  if (!auth || auth !== `Bearer ${API_KEY}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { text, secret } = req.body;
    if (!text || !secret) return res.status(400).json({ error: "Missing text or secret" });

    const key = crypto.createHash("sha256").update(secret).digest();
    const cipher = crypto.createCipheriv("aes-256-ecb", key, null);

    let encrypted = cipher.update(text, "utf8", "base64");
    encrypted += cipher.final("base64");

    return res.status(200).json({ encrypted });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}
