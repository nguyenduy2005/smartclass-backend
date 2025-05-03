require('dotenv').config(); // Load biến môi trường từ file .env
const express = require('express');
const admin = require('firebase-admin');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const cors = require('cors');

if (!process.env.FB_PRIVATE_KEY) {
  console.error("❌ Thiếu biến môi trường FB_PRIVATE_KEY");
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FB_PROJECT_ID,
    clientEmail: process.env.FB_CLIENT_EMAIL,
    privateKey: process.env.FB_PRIVATE_KEY.replace(/\\n/g, '\n')
  })
});

const db = admin.firestore();
const app = express();

// ✅ CORS cấu hình linh hoạt
app.use(cors({
  origin: 'https://myclass.web.app',
  methods: ['GET', 'POST'],
  credentials: false
}));
app.use(express.json());

// 🔐 Tạo secret và QR code
app.post('/enable-2fa', async (req, res) => {
  const { uid, username } = req.body;
  if (!uid || !username) return res.status(400).json({ message: 'Thiếu uid hoặc username' });

  try {
    const secret = speakeasy.generateSecret({ name: `SmartClass (${username})` });
    const otpauth_url = secret.otpauth_url;
    const qr = await qrcode.toDataURL(otpauth_url);

    await db.collection('users').doc(uid).set({
      twoFASecret: secret.base32,
      twoFAEnabled: false
    }, { merge: true });

    res.json({ qr });
  } catch (err) {
    console.error("❌ Lỗi khi bật 2FA:", err);
    res.status(500).json({ message: "Lỗi khi bật 2FA" });
  }
});

// ✅ Xác minh OTP
app.post('/verify-2fa', async (req, res) => {
  const { uid, token } = req.body;
  if (!uid || !token) return res.status(400).json({ message: 'Thiếu uid hoặc mã OTP' });

  try {
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
  } catch (err) {
    console.error("❌ Lỗi khi xác minh OTP:", err);
    res.status(500).json({ message: "Lỗi xác minh OTP" });
  }
});

// 🔊 Khởi động server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ 2FA backend đang chạy tại http://localhost:${PORT}`);
});