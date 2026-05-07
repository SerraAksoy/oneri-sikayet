// api/entries.js
// Google Sheets'ten tüm kayıtları okur (sadece yönetici paneli için)
import crypto from "crypto";
export default async function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const SHEET_ID = process.env.GOOGLE_SHEET_ID;
  const API_KEY_OR_SA = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;

  try {
    const token = await getAccessToken(API_KEY_OR_SA);

    const url = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/Kayıtlar!A:G`;
    const response = await fetch(url, {
      headers: { 'Authorization': `Bearer ${token}` },
    });

    if (!response.ok) throw new Error('Sheets okuma hatası');

    const data = await response.json();
    const rows = data.values || [];

    // İlk satır başlık ise atla, kalan satırları parse et
    const dataRows = rows.length > 1 ? rows.slice(1) : [];

    const entries = dataRows.map((row, idx) => ({
      ref:      row[0] || '',
      category: row[1] || '',
      message:  row[2] || '',
      date:     row[3] || '',
      status:   row[4] || 'Bekliyor',
      notes:    row[5] || '',
      rowIndex: idx + 2, // Sheets satır numarası (1-indexed + başlık satırı)
    })).reverse(); // En yeni kayıtlar önce

    return res.status(200).json(entries);
  } catch (error) {
    console.error('Entries error:', error);
    return res.status(500).json({ error: 'Veriler alınamadı' });
  }
}

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
