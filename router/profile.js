const express = require('express');
const router = express.Router();
const cloudinary = require('cloudinary').v2;
const upload = require('../models/multer'); // आपका multer पाथ
const mongoose = require('mongoose');
const User = mongoose.model('User'); 
// ध्यान दें: server.js में authMiddleware स्थानीय (local) है, 
// इसलिए हम इसे यहाँ अलग से इम्पोर्ट नहीं कर रहे हैं, क्योंकि server.js ने इसे पहले ही वेरीफाई कर दिया है।

// Cloudinary कॉन्फ़िगरेशन
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// प्रोफाइल फोटो अपलोड/अपडेट करने का API राउट
router.put('/update-profile-pic', upload.single('profilePic'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "कृपया एक फ़ाइल चुनें" });
    }

    // फ़ाइल को Cloudinary पर अपलोड करें
    const result = await cloudinary.uploader.upload(req.file.path, {
      folder: "shopzilla_profiles",
    });

    // ध्यान दें: यहाँ req.user.userId लिखा है, क्योंकि आपकी server.js में यही सेट है
    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId, 
      { profilePic: result.secure_url },
      { new: true }
    ).select("-password");

    res.status(200).json({
      success: true,
      message: "प्रोफाइल फोटो सफलतापूर्वक अपडेट हो गई",
      user: updatedUser
    });

  } catch (error) {
    console.error("Cloudinary Upload Error:", error);
    res.status(500).json({ message: "सर्वर एरर, अपलोड असफल रहा" });
  }
});

// प्रोफाइल का लेटेस्ट डेटा (फोटो के साथ) प्राप्त करने का राउट
router.get('/profile-details', async (req, res) => {
  try {
    // req.user.userId आपके server.js के authMiddleware से पास होकर यहाँ आएगा
    const user = await User.findById(req.user.userId).select("-password -otp -otpExpires -__v");
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json({
      success: true,
      user
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error: error.message });
  }
});


module.exports = router;
