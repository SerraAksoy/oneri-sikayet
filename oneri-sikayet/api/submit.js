// api/submit.js
// Çalışanların gönderdiği anonim mesajları Google Sheets'e kaydeder

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

// Service Account ile Google OAuth2 token al
async function getAccessToken(serviceAccountJson) {
  const sa = JSON.parse(serviceAccountJson);
  const now = Math.floor(Date.now() / 1000);

  const header = btoa(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = btoa(JSON.stringify({
    iss: sa.client_email,
    scope: 'https://www.googleapis.com/auth/spreadsheets',
    aud: 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
  }));

  const jwtUnsigned = `${header}.${payload}`;
  const privateKey = sa.private_key;

  // Vercel Edge'de crypto.subtle ile imzala
  const keyData = privateKey
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\n/g, '');

  const binaryKey = Uint8Array.from(atob(keyData), c => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8', binaryKey.buffer,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false, ['sign']
  );

  const encoder = new TextEncoder();
  const signatureBuffer = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', cryptoKey, encoder.encode(jwtUnsigned));
  const signature = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)));
  const jwt = `${jwtUnsigned}.${signature}`;

  const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${jwt}`,
  });

  const tokenData = await tokenResponse.json();
  return tokenData.access_token;
}
