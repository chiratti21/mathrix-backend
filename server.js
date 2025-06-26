require('dotenv').config(); 

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();

const PORT = process.env.PORT || 5000; 

// --- Middleware ---
app.use(express.json());


const frontendUrl = process.env.FRONTEND_URL; 
if (frontendUrl) {
  app.use(cors({
    origin: frontendUrl, // อนุญาตเฉพาะ Frontend URL ที่กำหนด
    optionsSuccessStatus: 200
  }));
  console.log(`CORS enabled for origin: ${frontendUrl}`);
} else {
 
  app.use(cors()); 
  console.warn("CORS is open to all origins as FRONTEND_URL is not set. This is not recommended for production.");
}


// --- MongoDB Connection ---
const mongoURI = process.env.MONGO_URI;

// ตรวจสอบว่า MONGO_URI ถูกกำหนดค่าแล้ว
if (!mongoURI) {
  console.error('MongoDB connection error: MONGO_URI is not defined in environment variables.');
  
} else {
  mongoose.connect(mongoURI)
    .then(() => console.log('MongoDB connected successfully!'))
    .catch(err => {
      console.error('MongoDB connection error:', err.message);
     
    });
}

// --- User Schema and Model ---
const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const User = mongoose.model('User', UserSchema);

// @route   POST /api/register
// @desc    Register user
// @access  Public
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;

  // ตรวจสอบว่าเชื่อมต่อ MongoDB สำเร็จก่อนทำอะไร
  if (mongoose.connection.readyState !== 1) { // 1 = connected
    console.error('MongoDB is not connected. Cannot process registration.');
    return res.status(503).json({ msg: 'Database service unavailable. Please try again later.' });
  }

  try {
    let user = await User.findOne({ username });
    if (user) {
      return res.status(400).json({ msg: 'Username already exists.' });
    }

    user = new User({
      username,
      password
    });

    await user.save();
    res.status(201).json({ msg: 'User registered successfully!' });

  } catch (err) {
    console.error('Registration error:', err.message);
    if (err.code === 11000) { // Duplicate key error (for unique username)
      return res.status(400).json({ msg: 'Username already exists.' });
    }
    res.status(500).json({ msg: 'Server Error during registration. Please check server logs for details.' });
  }
});

// @route   POST /api/login
// @desc    Authenticate user & get token (conceptual)
// @access  Public
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  // ตรวจสอบว่าเชื่อมต่อ MongoDB สำเร็จก่อนทำอะไร
  if (mongoose.connection.readyState !== 1) { // 1 = connected
    console.error('MongoDB is not connected. Cannot process login.');
    return res.status(503).json({ msg: 'Database service unavailable. Please try again later.' });
  }

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(400).json({ msg: 'Invalid Credentials (username not found)' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Invalid Credentials (incorrect password)' });
    }

    res.json({ msg: 'Logged in successfully!', username: user.username });

  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ msg: 'Server Error during login. Please check server logs for details.' });
  }
});


app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

