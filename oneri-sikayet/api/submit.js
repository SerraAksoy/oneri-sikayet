// api/submit.js
// Çalışanların gönderdiği anonim mesajları Google Sheets'e kaydeder
import crypto from "crypto";
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { category, message, ref } = req.body;

  if (!category || !message || message.length < 10) {
    return res.status(400).json({ error: 'Geçersiz veri' });
  }

  const SHEET_ID = process.env.GOOGLE_SHEET_ID;
  const API_KEY_OR_SA = process.env.GOOGLE_SERVICE_ACCOUNT_KEY; // JSON string

  try {
    const token = await getAccessToken(API_KEY_OR_SA);
    const now = new Date();
    const dateStr = now.toLocaleDateString('tr-TR') + ' ' + now.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });

    // Google Sheets'e satır ekle
    const appendUrl = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/Kayıtlar!A:F:append?valueInputOption=USER_ENTERED`;

    const response = await fetch(appendUrl, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        values: [[ref, category, message, dateStr, 'Bekliyor', '']]
        // Sütunlar: Referans | Kategori | Mesaj | Tarih | Durum | Notlar
      }),
    });

    if (!response.ok) {
      const err = await response.text();
      throw new Error('Sheets API hatası: ' + err);
    }

    return res.status(200).json({ success: true, ref });
  } catch (error) {
    console.error('Submit error:', error);
    return res.status(500).json({ error: 'Sunucu hatası' });
  }
}

async function getAccessToken(serviceAccountJson) {
  if (!serviceAccountJson) {
    throw new Error("GOOGLE_SERVICE_ACCOUNT_KEY eksik");
  }

  const sa = JSON.parse(serviceAccountJson);
  const now = Math.floor(Date.now() / 1000);

  const base64url = (input) =>
    Buffer.from(JSON.stringify(input))
      .toString("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");

  const header = base64url({ alg: "RS256", typ: "JWT" });

  const payload = base64url({
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/spreadsheets",
    aud: "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  });

  const unsignedJwt = `${header}.${payload}`;

  const privateKey = sa.private_key.replace(/\\n/g, "\n");

  const signature = crypto
    .createSign("RSA-SHA256")
    .update(unsignedJwt)
    .sign(privateKey, "base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");

  const jwt = `${unsignedJwt}.${signature}`;

  const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });

  const tokenData = await tokenResponse.json();

  if (!tokenResponse.ok) {
    throw new Error("Google token hatası: " + JSON.stringify(tokenData));
  }

  return tokenData.access_token;
}
