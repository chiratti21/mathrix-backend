require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;

// --- Middleware ---
app.use(cors());
app.use(express.json());

// --- MongoDB Connection ---
const mongoURI = process.env.MONGO_URI;

mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected successfully!'))
  .catch(err => {
    console.error('MongoDB connection error:', err.message);
    process.exit(1); // Exit process with failure
  });

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
    res.status(201).json({ msg: 'User registered successfully!' }); // Send 201 for resource creation

  } catch (err) {
    console.error('Registration error:', err.message);
    // Always send a JSON response
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