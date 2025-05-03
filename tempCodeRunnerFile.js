const express = require('express');
const admin = require('firebase-admin');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const cors = require('cors');

const serviceAccount = require('./serviceAccountKey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const app = express();
app.use(express.json());
app.use(cors()); // nếu frontend và backend khác cổng

// 🔐 Tạo secret và lưu vào Firestore
app.post('/enable-2fa', async (req, res) => {
  const { uid, username } = req.body;
  if (!uid || !username) return res.status(400).json({ message: 'Thiếu uid hoặc username' });

  const secret = speakeasy.generateSecret({ name: `SmartClass (${username})` });
  const otpauth_url = secret.otpauth_url;
  const qr = await qrcode.toDataURL(otpauth_url);

  await db.collection('users').doc(uid).set({
    twoFASecret: secret.base32,
    twoFAEnabled: false
  }, { merge: true });

  res.json({ qr });
});

// ✅ Xác minh mã OTP từ app
app.post('/verify-2fa', async (req, res) => {
  const { uid, token } = req.body;
  if (!uid || !token) return res.status(400).json({ message: 'Thiếu uid hoặc mã OTP' });

  const userDoc = await db.collection('users').doc(uid).get();
  if (!userDoc.exists) return res.status(404).json({ message: 'Không tìm thấy người dùng' });

  const { twoFASecret } = userDoc.data();
  const verified = speakeasy.totp.verify({
    secret: twoFASecret,
    encoding: 'base32',
    token,
    window: 1
  });

  if (verified) {
    await db.collection('users').doc(uid).update({ twoFAEnabled: true });
    return res.json({ success: true });
  } else {
    return res.status(401).json({ success: false, message: 'Mã không hợp lệ' });
  }
});

app.listen(3000, () => {
  console.log("2FA backend đang chạy tại http://localhost:3000");
});