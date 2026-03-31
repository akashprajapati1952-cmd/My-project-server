require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;

// --- MongoDB Connection ---
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected Successfully!"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err));

// --- User Schema ---
// --- User Schema ---
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  // Map use karne se aapka { "1": 5 } wala format chal jayega
  cart: {
    type: Map,
    of: Number,
    default: {}
  }
});


const User = mongoose.model('User', userSchema);

// --- Signup API ---
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    const token = jwt.sign({ userId: newUser._id }, JWT_SECRET, { expiresIn: '24h' });

    res.status(201).json({ 
      message: "Signup successful!", 
      token, 
      user: { name: newUser.name, email: newUser.email, cart: newUser.cart } 
    });
  } catch (err) {
    // Isse aapko Termux mein asli error dikhega
    console.error("Signup Error Details:", err); 
    res.status(500).json({ message: "Signup error", error: err.message });
  }
});






// 2. Login API
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
      user: { name: user.name, email: user.email, cart: user.cart || [] } 
    });
  } catch (err) {
    res.status(500).json({ message: "Login error", error: err.message });
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

app.get('/api/user/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ 
      message: "User details fetched successfully", 
      user: { name: user.name, email: user.email, cart: user.cart || []} 
    });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});
app.post('/api/user/update-cart', authMiddleware, async (req, res) => {
  try {
    const { cartData } = req.body; // Yahan { "1": 5, "2": 6 } aayega

    // User find karein aur naya cart save karein
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
