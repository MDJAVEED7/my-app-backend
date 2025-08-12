const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  aadhaarHash: { type: String, required: true, unique: true },
  aadhaarLast4: { type: String, required: true }, // for display only
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);
