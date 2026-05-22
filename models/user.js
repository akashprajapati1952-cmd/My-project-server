const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true
  },

  email: {
    type: String,
    required: true,
    unique: true
  },

  password: {
    type: String,
    required: true
  },

  cart: {
    type: Map,
    of: Number,
    default: {}
  },

  // प्रोफाइल फोटो के लिए नई फ़ील्ड
  profilePic: {
    type: String,
    default: "" // शुरुआत में यह खाली रहेगी, जब तक यूज़र अपलोड न करे
  },

  // OTP fields
  otp: {
    type: String,
    default: null
  },

  otpExpires: {
    type: Date,
    default: null
  }
}, { timestamps: true }); // (Optional) timestamps डालने से createdAt और updatedAt भी ट्रैक होता रहेगा

const User = mongoose.model('User', userSchema);
module.exports = User;
