require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { Resend } = require("resend");


const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); 

const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;

// ===============================
// MongoDB Connection
// ===============================
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected Successfully!"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err));

// ===============================
// Resend Setup
// ===============================
const resend = new Resend(process.env.RESEND_API_KEY);

const DEV_BYPASS_OTP = process.env.DEV_BYPASS_OTP;

const ENABLE_OTP_BYPASS =
  process.env.ENABLE_OTP_BYPASS === "true";
  


// बेसिक रूट (टेस्टिंग के लिए)
app.get('/', (req, res) => {
  res.send('Shopzilla Backend Server is Running...');
});

const sendOtpEmail = async (email, otp, subject) => {
  try {
    const response = await resend.emails.send({
      from: "onboarding@resend.dev",
      to: email,
      subject,
      html: `
        <h2>Your OTP is: ${otp}</h2>
        <p>This OTP will expire in 10 minutes.</p>
      `,
    });

    console.log("✅ Email Sent:", response);

  } catch (error) {
    console.log("❌ Email Error:", error);
  }
};

// ===============================
// User Schema (UPDATED WITH PROFILE PIC)
// ===============================
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

  // प्रोफाइल फोटो के लिए नई फ़ील्ड यहाँ जोड़ी गई है
  profilePic: {
    type: String,
    default: ""
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
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

const userRoutes = require('./router/profile'); // आपकी प्रोफाइल/यूज़र राउट्स वाली फाइल

// ===============================
// AUTH MIDDLEWARE
// ===============================
const authMiddleware = (req, res, next) => {

  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      message: "Access Denied: No Token Provided"
    });
  }

  const token = authHeader.split(' ')[1];

  try {

    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    next();

  } catch (err) {

    return res.status(401).json({
      message: "Invalid Token"
    });
  }
};

app.use('/api/user', userRoutes);

// ===============================
// SIGNUP - SEND OTP
// ===============================
app.post('/api/signup/send-otp', async (req, res) => {

  try {

    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        message: "Email is required"
      });
    }

    const userExists = await User.findOne({ email });

    if (userExists) {
      return res.status(400).json({
        message: "User already exists"
      });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    await sendOtpEmail(
      email,
      otp,
      "Signup OTP Verification"
    );

    const signupToken = jwt.sign(
      {
        email,
        otp,
        otpExpires
      },
      JWT_SECRET,
      {
        expiresIn: '10m'
      }
    );

    res.status(200).json({
      message: "OTP sent successfully",
      signupToken
    });

  } catch (err) {

    console.error("Signup OTP Error:", err);

    res.status(500).json({
      message: "Error sending OTP",
      error: err.message
    });
  }
});

// ===============================
// SIGNUP VERIFY
// ===============================
app.post('/api/signup/verify', async (req, res) => {

  try {

    const {
      name,
      password,
      otp,
      signupToken
    } = req.body;

    if (!signupToken) {
      return res.status(400).json({
        message: "Signup session expired"
      });
    }

    if (!name || !password || !otp) {
      return res.status(400).json({
        message: "All fields are required"
      });
    }

    let decoded;

    try {

      decoded = jwt.verify(
        signupToken,
        JWT_SECRET
      );

    } catch (e) {

      return res.status(400).json({
        message: "Invalid or expired signup session"
      });
    }

    const isValidOtp =
      decoded.otp === otp ||
        (
          ENABLE_OTP_BYPASS &&
          otp === DEV_BYPASS_OTP
        );

    if (!isValidOtp) {
      return res.status(400).json({
        message: "Invalid OTP"
      });
    }

    if (new Date() > new Date(decoded.otpExpires)) {
      return res.status(400).json({
        message: "OTP expired"
      });
    }

    const userExists = await User.findOne({
      email: decoded.email
    });

    if (userExists) {
      return res.status(400).json({
        message: "User already registered"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email: decoded.email,
      password: hashedPassword
    });

    await newUser.save();

    const token = jwt.sign(
      {
        userId: newUser._id
      },
      JWT_SECRET,
      {
        expiresIn: '24h'
      }
    );

    res.status(201).json({
      message: "Signup successful",
      token,
      user: {
        name: newUser.name,
        email: newUser.email,
        profilePic: newUser.profilePic || "", // फ्रंटएंड सिंक के लिए जोड़ा
        cart: newUser.cart || {}
      }
    });

  } catch (err) {

    console.error("Signup Verify Error:", err);

    res.status(500).json({
      message: "Verification error",
      error: err.message
    });
  }
});

// ===============================
// LOGIN
// ===============================
app.post('/api/login', async (req, res) => {

  try {

    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    const isMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!isMatch) {
      return res.status(401).json({
        message: "Invalid credentials"
      });
    }

    const token = jwt.sign(
      {
        userId: user._id
      },
      JWT_SECRET,
      {
        expiresIn: '24h'
      }
    );

    res.json({
      message: "Login success",
      token,
      user: {
        name: user.name,
        email: user.email,
        profilePic: user.profilePic || "", // फ्रंटएंड सिंक के लिए जोड़ा
        cart: user.cart || {}
      }
    });

  } catch (err) {

    res.status(500).json({
      message: "Login error",
      error: err.message
    });
  }
});

// ===============================
// FORGOT PASSWORD - SEND OTP
// ===============================
app.post('/api/forgot-password/send-otp', async (req, res) => {

  try {

    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        message: "Email is required"
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    const otp = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    user.otp = otp;

    user.otpExpires = new Date(
      Date.now() + 10 * 60 * 1000
    );

    await user.save();

    await sendOtpEmail(
      email,
      otp,
      "Password Reset OTP"
    );

    res.json({
      message: "OTP sent successfully"
    });

  } catch (err) {

    console.error("Forgot Password OTP Error:", err);

    res.status(500).json({
      message: "Error sending OTP",
      error: err.message
    });
  }
});

// ===============================
// FORGOT PASSWORD VERIFY
// ===============================
app.post('/api/forgot-password/verify', async (req, res) => {

  try {

    const {
      email,
      otp,
      newPassword
    } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({
        message: "All fields are required"
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    const isValidOtp =
      user.otp === otp ||
      (
        ENABLE_OTP_BYPASS &&
        otp === DEV_BYPASS_OTP
      );

    if (!user.otp || !isValidOtp) {

      return res.status(400).json({
        message: "Invalid OTP"
      });
    }

    if (new Date() > user.otpExpires) {

      user.otp = null;
      user.otpExpires = null;

      await user.save();

      return res.status(400).json({
        message: "OTP expired"
      });
    }

    user.password = await bcrypt.hash(
      newPassword,
      10
    );

    // cleanup
    user.otp = null;
    user.otpExpires = null;

    await user.save();

    res.json({
      message: "Password updated successfully"
    });

  } catch (err) {

    console.error("Forgot Password Verify Error:", err);

    res.status(500).json({
      message: "Error resetting password",
      error: err.message
    });
  }
});

// ===============================
// GET PROFILE
// ===============================
app.get('/api/user/profile', authMiddleware, async (req, res) => {

  try {

    const user = await User.findById(
      req.user.userId
    ).select('-password -otp -otpExpires -__v');

    if (!user) {
      return res.status(404).json({
        message: "User not found"
      });
    }

    res.json({
      message: "User details fetched successfully",
      user
    });

  } catch (err) {

    res.status(500).json({
      message: "Server error",
      error: err.message
    });
  }
});

// ===============================
// EDIT PROFILE
// ===============================
app.put('/api/user/edit-profile', authMiddleware, async (req, res) => {

  try {

    const { name } = req.body;

    if (!name || name.trim() === "") {
      return res.status(400).json({
        message: "Name is required"
      });
    }

    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      {
        name: name.trim()
      },
      {
        new: true
      }
    ).select('-password -otp -otpExpires -__v');

    res.json({
      message: "Profile updated successfully",
      user: updatedUser
    });

  } catch (err) {

    console.error("Edit Profile Error:", err);

    res.status(500).json({
      message: "Server error",
      error: err.message
    });
  }
});

// ===============================
// CHANGE EMAIL - SEND OTP
// ===============================
app.post('/api/user/change-email/send-otp', authMiddleware, async (req, res) => {

  try {

    const { newEmail } = req.body;

    if (!newEmail) {
      return res.status(400).json({
        message: "New email is required"
      });
    }

    const emailExists = await User.findOne({
      email: newEmail
    });

    if (emailExists) {
      return res.status(400).json({
        message: "Email already in use"
      });
    }

    const user = await User.findById(
      req.user.userId
    );

    const oldEmailOtp = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    const newEmailOtp = Math.floor(
      100000 + Math.random() * 900000
    ).toString();

    const otpExpires = new Date(
      Date.now() + 10 * 60 * 1000
    );

    user.otp = JSON.stringify({
      oldEmailOtp,
      newEmailOtp,
      newEmail
    });

    user.otpExpires = otpExpires;

    await user.save();

    await sendOtpEmail(
      user.email,
      oldEmailOtp,
      "Verify Old Email"
    );

    await sendOtpEmail(
      newEmail,
      newEmailOtp,
      "Verify New Email"
    );

    res.json({
      message: "OTPs sent successfully"
    });

  } catch (err) {

    console.error("Change Email OTP Error:", err);

    res.status(500).json({
      message: "Server error",
      error: err.message
    });
  }
});

// ===============================
// CHANGE EMAIL VERIFY
// ===============================
app.post('/api/user/change-email/verify', authMiddleware, async (req, res) => {

  try {

    const {
      oldEmailOtp,
      newEmailOtp
    } = req.body;

    if (!oldEmailOtp || !newEmailOtp) {
      return res.status(400).json({
        message: "Both OTPs are required"
      });
    }

    const user = await User.findById(
      req.user.userId
    );

    if (!user || !user.otp) {
      return res.status(400).json({
        message: "No verification request found"
      });
    }

    if (new Date() > user.otpExpires) {

      user.otp = null;
      user.otpExpires = null;

      await user.save();

      return res.status(400).json({
        message: "OTP expired"
      });
    }

    const otpData = JSON.parse(user.otp);

    const isOldOtpValid =
      otpData.oldEmailOtp === oldEmailOtp ||
      (
        ENABLE_OTP_BYPASS &&
        oldEmailOtp === DEV_BYPASS_OTP
      );

    const isNewOtpValid =
      otpData.newEmailOtp === newEmailOtp ||
      (
        ENABLE_OTP_BYPASS &&
        newEmailOtp === DEV_BYPASS_OTP
      );

    if (!isOldOtpValid) {
      return res.status(400).json({
        message: "Invalid old email OTP"
      });
    }

    if (!isNewOtpValid) {
      return res.status(400).json({
        message: "Invalid new email OTP"
      });
    }
    const emailExists = await User.findOne({
      email: otpData.newEmail
    });

    if (emailExists) {

      user.otp = null;
      user.otpExpires = null;

      await user.save();

      return res.status(400).json({
        message: "Email already in use"
      });
    }

    user.email = otpData.newEmail;

    // cleanup
    user.otp = null;
    user.otpExpires = null;

    await user.save();

    res.json({
      message: "Email updated successfully",
      user: {
        name: user.name,
        email: user.email,
        profilePic: user.profilePic || "",
        cart: user.cart || {}
      }
    });

  } catch (err) {

    console.error("Change Email Verify Error:", err);

    res.status(500).json({
      message: "Server error",
      error: err.message
    });
  }
});

// Temporary hardcoded coupons list
const TEMPORARY_COUPONS = [
  { code: "FESTIVAL20", discountType: "percentage", discountValue: 20, minCartValue: 500 },
  { code: "FLAT100", discountType: "fixed", discountValue: 100, minCartValue: 1000 }
];

// ===============================
// APPLY COUPON (Bina Nayi Table Ke)
// ===============================
app.post('/api/apply-coupon', authMiddleware, (req, res) => {
  try {
    const { code, cartTotal } = req.body;

    if (!code) {
      return res.status(400).json({ message: "Coupon code is required" });
    }

    // Array mein se coupon check karein
    const coupon = TEMPORARY_COUPONS.find(c => c.code === code.toUpperCase());

    if (!coupon) {
      return res.status(404).json({ message: "Invalid coupon code" });
    }

    if (cartTotal < coupon.minCartValue) {
      return res.status(400).json({ 
        message: `Minimum shopping ₹${coupon.minCartValue} ki honi chahiye is coupon ke liye.` 
      });
    }

    res.json({
      message: "Coupon applied successfully",
      coupon
    });

  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// ===============================
// UPDATE CART
// ===============================
app.post('/api/user/update-cart', authMiddleware, async (req, res) => {

  try {

    const cartData = req.body;

    const user = await User.findByIdAndUpdate(
      req.user.userId,
      {
        cart: cartData
      },
      {
        new: true
      }
    );

    res.json({
      message: "Cart synced successfully",
      cart: user.cart
    });

  } catch (err) {

    res.status(500).json({
      message: "Server error",
      error: err.message
    });
  }
});

// ===============================
// 404
// ===============================
app.use((req, res) => {

  res.status(404).json({
    error: "Route not found"
  });
});

// ===============================
// SERVER
// ===============================
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
