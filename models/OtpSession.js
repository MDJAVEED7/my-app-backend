const mongoose = require('mongoose');

const otpSchema = new mongoose.Schema({
  aadhaarHash: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  otp: { type: String, required: true },
  expiresAt: { type: Date, required: true }
});

module.exports = mongoose.model('OtpSession', otpSchema);
