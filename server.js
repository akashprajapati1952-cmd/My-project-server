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

const JWT_SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI;

// --- MongoDB Connection ---
mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected Successfully!"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err));



const resend = new Resend(process.env.RESEND_API_KEY);

const sendOtpEmail = async (email, otp, subject) => {
  try {
    const response = await resend.emails.send({
      from: "onboarding@resend.dev",
      to: email,
      subject: subject,
      html: `
        <h2>Your OTP is: ${otp}</h2>
        <p>This OTP will expire in 5 minutes.</p>
      `,
    });

    console.log(response);

  } catch (error) {
    console.log("Email Error:", error);
  }
};




// --- User Schema ---
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  cart: {
    type: Map,
    of: Number,
    default: {}
  },
  // Fields for temporary storage of OTP
  otp: { type: String, default: null },
  otpExpires: { type: Date, default: null }
});

const User = mongoose.model('User', userSchema);

// --- 1. SIGNUP FLOW WITH OTP ---

// Step A: Send OTP for Signup
app.post('/api/signup/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required" });
    
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: "User already exists" });

    // Generate 6 digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 mins validity

    await sendOtpEmail(email, otp, "Signup OTP Verification");

    // Secure temporary session token so we don't have to save unverified user data in DB
    const signupToken = jwt.sign({ email, otp, otpExpires }, JWT_SECRET, { expiresIn: '10m' });

    res.status(200).json({ message: "OTP sent successfully to your email", signupToken });
  } catch (err) {
    console.error("Signup OTP Error Details:", err);
    res.status(500).json({ message: "Error sending OTP", error: err.message });
  }
});

// Step B: Verify OTP & Complete Registration
app.post('/api/signup/verify', async (req, res) => {
  try {
    const { name, password, otp, signupToken } = req.body;

    if (!signupToken) return res.status(400).json({ message: "Signup session expired or token missing" });
    if (!name || !password || !otp) return res.status(400).json({ message: "All fields are required" });

    // Decode token and verify details
    let decoded;
    try {
      decoded = jwt.verify(signupToken, JWT_SECRET);
    } catch (e) {
      return res.status(400).json({ message: "Invalid or expired signup token session" });
    }
    
    if (decoded.otp !== otp) return res.status(400).json({ message: "Invalid OTP" });
    if (new Date() > new Date(decoded.otpExpires)) return res.status(400).json({ message: "OTP has expired" });

    const userExists = await User.findOne({ email: decoded.email });
    if (userExists) return res.status(400).json({ message: "User already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email: decoded.email, password: hashedPassword });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({ 
      message: "Signup successful!", 
      token, 
      user: { name: newUser.name, email: newUser.email, cart: newUser.cart } 
    });
  } catch (err) {
    console.error("Signup Verification Error Details:", err);
    res.status(500).json({ message: "Verification error", error: err.message });
  }
});
// --- Middleware & Profile Route ---
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: "Access Denied: No Token Provided" });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; 
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid Token" });
  }
};

// ===============================
// EDIT PROFILE (ONLY NAME)
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
      { name: name.trim() },
      { new: true }
    ).select('-password');

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
// SEND OTPs FOR EMAIL CHANGE
// ===============================
app.post('/api/user/change-email/send-otp', authMiddleware, async (req, res) => {
  try {
    const { newEmail } = req.body;

    if (!newEmail) {
      return res.status(400).json({
        message: "New email is required"
      });
    }

    // Check if new email already exists
    const emailExists = await User.findOne({ email: newEmail });

    if (emailExists) {
      return res.status(400).json({
        message: "Email already in use"
      });
    }

    const user = await User.findById(req.user.userId);

    // Generate OTPs
    const oldEmailOtp = Math.floor(100000 + Math.random() * 900000).toString();

    const newEmailOtp = Math.floor(100000 + Math.random() * 900000).toString();

    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    // Save temporarily
    user.otp = JSON.stringify({
      oldEmailOtp,
      newEmailOtp,
      newEmail
    });

    user.otpExpires = otpExpires;

    await user.save();

    // Send OTP to OLD email
    await sendOtpEmail(
      user.email,
      oldEmailOtp,
      "Verify Old Email"
    );

    // Send OTP to NEW email
    await sendOtpEmail(
      newEmail,
      newEmailOtp,
      "Verify New Email"
    );

    res.json({
      message: "OTPs sent to both email addresses"
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
// VERIFY BOTH OTPs & CHANGE EMAIL
// ===============================
app.post('/api/user/change-email/verify', authMiddleware, async (req, res) => {
  try {
    const { oldEmailOtp, newEmailOtp } = req.body;

    if (!oldEmailOtp || !newEmailOtp) {
      return res.status(400).json({
        message: "Both OTPs are required"
      });
    }

    const user = await User.findById(req.user.userId);

    if (!user || !user.otp) {
      return res.status(400).json({
        message: "No verification request found"
      });
    }

    // Expiry check
    if (new Date() > user.otpExpires) {
      return res.status(400).json({
        message: "OTP expired"
      });
    }

    // Parse stored data
    const otpData = JSON.parse(user.otp);

    // Verify OTPs
    if (otpData.oldEmailOtp !== oldEmailOtp) {
      return res.status(400).json({
        message: "Invalid old email OTP"
      });
    }

    if (otpData.newEmailOtp !== newEmailOtp) {
      return res.status(400).json({
        message: "Invalid new email OTP"
      });
    }

    // Final duplicate email check
    const emailExists = await User.findOne({
      email: otpData.newEmail
    });

    if (emailExists) {
      return res.status(400).json({
        message: "Email already in use"
      });
    }

    // Update email
    user.email = otpData.newEmail;

    // Cleanup
    user.otp = null;
    user.otpExpires = null;

    await user.save();

    res.json({
      message: "Email updated successfully",
      user: {
        name: user.name,
        email: user.email,
        cart: user.cart || {}
      }
    });

  } catch (err) {
    console.error("Verify Email Change Error:", err);

    res.status(500).json({
      message: "Server error",
      error: err.message
    });
  }
});
// --- 2. LOGIN API ---
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    if (!user) return res.status(404).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ 
      message: "Login success", 
      token, 
      user: { name: user.name, email: user.email, cart: user.cart || {} } 
    });
  } catch (err) {
    res.status(500).json({ message: "Login error", error: err.message });
  }
});

// --- 3. FORGOT PASSWORD FLOW ---

// Step A: Send OTP for Password Reset
app.post('/api/forgot-password/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User with this email does not exist" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    
    user.otp = otp;
    user.otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 mins validity
    await user.save();

    await sendOtpEmail(email, otp, "Password Reset OTP");

    res.json({ message: "OTP sent to your registered email ID" });
  } catch (err) {
    console.error("Forgot Password OTP Error Details:", err);
    res.status(500).json({ message: "Error sending OTP", error: err.message });
  }
});

// Step B: Verify OTP & Reset Password
app.post('/api/forgot-password/verify', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) return res.status(400).json({ message: "All fields are required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    if (!user.otp || user.otp !== otp) return res.status(400).json({ message: "Invalid OTP" });
    if (new Date() > user.otpExpires) return res.status(400).json({ message: "OTP has expired" });

    // Hash and update the new password, then clean up the database fields
    user.password = await bcrypt.hash(newPassword, 10);
    user.otp = null;
    user.otpExpires = null;
    await user.save();

    res.json({ message: "Password updated successfully! You can now log in." });
  } catch (err) {
    console.error("Forgot Password Reset Error Details:", err);
    res.status(500).json({ message: "Error resetting password", error: err.message });
  }
});



app.get('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ 
      message: "User details fetched successfully", 
      user: { name: user.name, email: user.email, cart: user.cart || {} } 
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.post('/api/user/update-cart', authMiddleware, async (req, res) => {
  try {
    const cartData = req.body; 

    const user = await User.findByIdAndUpdate(
      req.user.userId, 
      { cart: cartData }, 
      { new: true }
    );

    res.json({ 
      message: "Cart synced successfully", 
      cart: user.cart 
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
