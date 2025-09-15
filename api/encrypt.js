import crypto from "crypto";

export default function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { text, secret } = req.body;

    if (!text || !secret) {
      return res.status(400).json({ error: "Missing text or secret" });
    }

    // Clave UTF-8 → Buffer
    let key = Buffer.from(secret, "utf8");

    // Rellenar con 0x00 hasta 32 bytes (como Java SecretKeySpec)
    if (key.length < 32) {
      const padded = Buffer.alloc(32);
      key.copy(padded);
      key = padded;
    } else if (key.length > 32) {
      key = key.slice(0, 32); // cortar si sobra
    }

    // AES-256-ECB con PKCS5Padding
    const cipher = crypto.createCipheriv("aes-256-ecb", key, null);
    cipher.setAutoPadding(true);

    let encrypted = cipher.update(text, "utf8", "base64");
    encrypted += cipher.final("base64");

    // URI Encode
    const encryptedUri = encodeURIComponent(encrypted);

    return res.status(200).json({ encrypted: encryptedUri });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
