const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose'); // mongoose जोड़ा गया

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = 'your_secret_key_123';

// --- MongoDB कनेक्शन (आपका असली लिंक) ---
const MONGO_URI = "mongodb+srv://akashprajapati1952_db_user:dWVN6zYiyRpWe1m6@akash-cluster.6bbdwki.mongodb.net/shopzilla?retryWrites=true&w=majority&appName=Akash-Cluster";

mongoose.connect(MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected Successfully!"))
  .catch(err => console.error("❌ MongoDB Connection Error:", err));

// --- User Schema (डेटाबेस का ढांचा) ---
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);

// --- APIs ---

// 1. Signup API
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    const userExists = await User.findOne({ email });
    if (userExists) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "Signup successful in MongoDB!" });
  } catch (err) {
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

    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ 
      message: "Login success", 
      token, 
      user: { name: user.name, email: user.email } 
    });
  } catch (err) {
    res.status(500).json({ message: "Login error", error: err.message });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: "Route not found" });
});

const PORT = 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
