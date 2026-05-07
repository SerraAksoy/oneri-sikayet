// api/update-status.js
// Yönetici panelinden durum güncellemelerini Google Sheets'e yazar

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { ref, status, rowIndex } = req.body;

  if (!ref || !status || !rowIndex) {
    return res.status(400).json({ error: 'Eksik parametre' });
  }

  const SHEET_ID = process.env.GOOGLE_SHEET_ID;
  const API_KEY_OR_SA = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;

  try {
    const token = await getAccessToken(API_KEY_OR_SA);

    // E sütunu = Durum (5. sütun)
    const range = `Kayıtlar!E${rowIndex}`;
    const url = `https://sheets.googleapis.com/v4/spreadsheets/${SHEET_ID}/values/${encodeURIComponent(range)}?valueInputOption=USER_ENTERED`;

    const response = await fetch(url, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ values: [[status]] }),
    });

    if (!response.ok) throw new Error('Güncelleme hatası');

    return res.status(200).json({ success: true });
  } catch (error) {
    console.error('Update status error:', error);
    return res.status(500).json({ error: 'Güncelleme başarısız' });
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
