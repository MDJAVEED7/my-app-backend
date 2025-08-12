const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const User = require('./models/User');
const OtpSession = require('./models/OtpSession');

dotenv.config();
const app = express();
app.use(cors());
app.use(express.json());

const hashAadhaar = (aadhaar) => {
  return crypto.createHmac('sha256', process.env.AADHAAR_SECRET)
               .update(aadhaar)
               .digest('hex');
};

const isValidAadhaarFormat = (s) => /^\d{12}$/.test(s);

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(()=> console.log('MongoDB connected'))
  .catch(err => { console.error(err); process.exit(1); });

// Step 1: Send OTP
app.post('/api/send-otp', async (req, res) => {
  const { aadhaar, name } = req.body;
  if (!aadhaar || !name) return res.status(400).json({ message: 'Missing fields' });
  if (!isValidAadhaarFormat(aadhaar)) return res.status(400).json({ message: 'Invalid Aadhaar' });

  const aadhaarHash = hashAadhaar(aadhaar);
  const existingUser = await User.findOne({ aadhaarHash });
  if (existingUser) return res.status(400).json({ message: 'User already registered' });

  const otp = Math.floor(100000 + Math.random() * 900000).toString(); 
  // 6-digit
  console.log(`Generated OTP for ${name} (${aadhaar}): ${otp}`); // simulate SMS

  await OtpSession.findOneAndUpdate(
    { aadhaarHash },
    { name, otp, expiresAt: new Date(Date.now() + 5 * 60 * 1000) },
    { upsert: true }
  );

  res.json({ message: `OTP sent successfully and otp is ${otp}` ,otp});
});
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { aadhaar, otp } = req.body;
    if (!aadhaar || !otp) return res.status(400).json({ message: 'Missing fields' });

    const aadhaarHash = hashAadhaar(aadhaar);
    const otpSession = await OtpSession.findOne({ aadhaarHash });

    if (!otpSession) return res.status(400).json({ message: 'No OTP session found' });
    if (otpSession.otp !== otp) return res.status(400).json({ message: 'Invalid OTP' });
    if (new Date() > otpSession.expiresAt) return res.status(400).json({ message: 'OTP expired' });

    res.json({ message: 'OTP verified successfully!' });
  } catch (err) {
    console.error('Error in /api/verify-otp:', err);
    res.status(500).json({ message: 'Something went wrong' });
  }
});

// Step 2: Verify OTP and register
app.post('/api/register', async (req, res) => {
  const { aadhaar, otp, password } = req.body;
  if (!aadhaar || !otp || !password) return res.status(400).json({ message: 'Missing fields' });

  const aadhaarHash = hashAadhaar(aadhaar);
  const otpSession = await OtpSession.findOne({ aadhaarHash });
  if (!otpSession) return res.status(400).json({ message: 'No OTP session found' });

  if (otpSession.otp !== otp) return res.status(400).json({ message: 'Invalid OTP' });
  if (new Date() > otpSession.expiresAt) return res.status(400).json({ message: 'OTP expired' });

  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({
    aadhaarHash,
    aadhaarLast4: aadhaar.slice(-4),
    password: hashedPassword
  });
  await newUser.save();
  await OtpSession.deleteOne({ aadhaarHash }); // remove used OTP

  res.status(201).json({ message: 'Registration successful' });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, ()=> console.log(`Server running on port ${PORT}`));
