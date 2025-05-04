require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const cors = require('cors');
if (!process.env.FB_PRIVATE_KEY) {
  console.error("❌ Thiếu biến môi trường FB_PRIVATE_KEY");
  console.log("ENV:", process.env);
  process.exit(1);
}

// ✅ Khởi tạo Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FB_PROJECT_ID,
    clientEmail: process.env.FB_CLIENT_EMAIL,
    privateKey: process.env.FB_PRIVATE_KEY.replace(/\\n/g, '\n'),
  }),
});

const db = admin.firestore();
const app = express();

// ✅ CORS cho cả local và production
app.use(cors({
  origin: [
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'http://localhost:3000',
    'https://myclass.web.app'
  ],
  methods: ['GET', 'POST'],
  credentials: false
}));
app.use(express.json());

/* ---------------------- API ENABLE 2FA ---------------------- */
app.post('/enable-2fa', async (req, res) => {
  const { uid, username } = req.body;
  if (!uid || !username) return res.status(400).json({ message: 'Thiếu uid hoặc username' });

  try {
    const secret = speakeasy.generateSecret({ name: `SmartClass (${username})` });
    const qr = await qrcode.toDataURL(secret.otpauth_url);

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

/* ---------------------- API VERIFY 2FA ---------------------- */
app.post('/verify-2fa', async (req, res) => {
  const { uid, token } = req.body;
  if (!uid || !token) return res.status(400).json({ message: 'Thiếu uid hoặc mã OTP' });

  try {
    const userDoc = await db.collection('users').doc(uid).get();
    if (!userDoc.exists) return res.status(404).json({ message: 'Không tìm thấy người dùng' });

    const { twoFASecret } = userDoc.data();
    if (!twoFASecret) return res.status(400).json({ message: "Người dùng chưa thiết lập 2FA" });

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

/* ---------------------- API DISABLE 2FA ---------------------- */
app.post('/disable-2fa', async (req, res) => {
  const { uid, token } = req.body;
  if (!uid || !token) return res.status(400).json({ message: 'Thiếu uid hoặc mã OTP' });

  try {
    const userDoc = await db.collection('users').doc(uid).get();
    if (!userDoc.exists) return res.status(404).json({ message: 'Không tìm thấy người dùng' });

    const { twoFASecret, twoFAEnabled } = userDoc.data();
    if (!twoFAEnabled || !twoFASecret) {
      return res.status(400).json({ message: "Người dùng chưa bật 2FA" });
    }

    const verified = speakeasy.totp.verify({
      secret: twoFASecret,
      encoding: 'base32',
      token,
      window: 1
    });

    if (!verified) {
      return res.status(401).json({ message: "Mã OTP không hợp lệ" });
    }

    await db.collection('users').doc(uid).update({
      twoFAEnabled: false,
      twoFASecret: admin.firestore.FieldValue.delete()
    });

    res.json({ success: true, message: "Đã tắt 2FA thành công" });
  } catch (err) {
    console.error("❌ Lỗi khi tắt 2FA:", err);
    res.status(500).json({ message: "Lỗi khi tắt 2FA" });
  }
});

/* ---------------------- START SERVER ---------------------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ 2FA backend đang chạy tại http://localhost:${PORT}`);
});