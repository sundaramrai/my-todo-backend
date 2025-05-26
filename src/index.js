// my-todo-backend/src/index.js
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
const corsOptions = {
  origin: [/^http:\/\/localhost(:[0-9]+)?$/, 'https://tascmaster.vercel.app', 'https://tascmaster.netlify.app'], 
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

app.use(cors(corsOptions));

// app.use(express.urlencoded({ extended: true })); // ✅ Parse URL-encoded bodies

app.use(express.json());

// MongoDB Connection
const MONGO_URI = process.env.MONGO_URI;

mongoose.connect(MONGO_URI, {
  serverSelectionTimeoutMS: 10000, // ⏳ Wait 10s before failing
})
  .then(() => console.log("✅ MongoDB Connected Successfully"))
  .catch(err => {
    console.error("❌ MongoDB Connection Error:", err.message);
    process.exit(1); // Exit the process if DB connection fails
  });

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phoneNumbers: [{ number: String }],
});

// Todo Schema
const todoSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  title: { type: String, required: true },
  description: { type: String },
  completed: { type: Boolean, default: false },
});

const User = mongoose.model('User', userSchema);
const Todo = mongoose.model('Todo', todoSchema);

const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Auth Routes
app.post('/api/register', async (req, res) => {
  try {
    const { email, username, password, phoneNumbers } = req.body;

    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({
        message: existingUser.email === email ? 'Email already exists' : 'Username already exists',
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ email, username, password: hashedPassword, phoneNumbers });
    await user.save();

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error("❌ Internal Server Error:", error);
    res.status(500).json({ message: 'Server error', error: error.message });

  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id, username: user.username }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, user: { username: user.username, email: user.email } });
  } catch (error) {
    console.error("❌ Internal Server Error:", error);
    res.status(500).json({ message: 'Server error', error: error.message });

  }
});

// Todo Routes
app.get('/api/todos', authenticateToken, async (req, res) => {
  try {
    const todos = await Todo.find({ userId: req.user?.userId });
    res.json(todos);
  } catch (error) {
    console.error("❌ Internal Server Error:", error);
    res.status(500).json({ message: 'Server error', error: error.message });

  }
});

app.post('/api/todos', authenticateToken, async (req, res) => {
  try {
    const { title, description } = req.body;
    const todo = new Todo({ userId: req.user?.userId, title, description, completed: false });
    await todo.save();
    res.status(201).json(todo);
  } catch (error) {
    console.error("❌ Internal Server Error:", error);
    res.status(500).json({ message: 'Server error', error: error.message });

  }
});

app.put('/api/todos/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    console.log("📝 Updating Todo with ID:", id, "for user:", req.user?.userId);
    console.log("📩 Update Data:", req.body);

    // ✅ Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(id)) {
      console.log("❌ Invalid Todo ID:", id);
      return res.status(400).json({ message: "Invalid Todo ID" });
    }

    const todo = await Todo.findOneAndUpdate(
      { _id: id, userId: req.user?.userId },
      req.body,
      { new: true }
    );

    if (!todo) {
      console.log("❌ Todo not found:", id);
      return res.status(404).json({ message: "Todo not found" });
    }

    console.log("✅ Todo updated successfully:", todo);
    res.json(todo);
  } catch (error) {
    console.error("❌ Error updating todo:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

app.put('/api/todos/:id/toggle', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    console.log("🔄 Toggling Todo with ID:", id, "for user:", req.user?.userId);

    // ✅ Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(id)) {
      console.log("❌ Invalid Todo ID:", id);
      return res.status(400).json({ message: "Invalid Todo ID" });
    }

    // ✅ Find the todo first
    const todo = await Todo.findOne({ _id: id, userId: req.user?.userId });

    if (!todo) {
      console.log("❌ Todo not found:", id);
      return res.status(404).json({ message: "Todo not found" });
    }

    // ✅ Toggle completion status
    todo.completed = !todo.completed;
    await todo.save(); // ✅ Ensure MongoDB updates the value

    console.log("✅ Todo completion toggled successfully:", todo);
    res.json(todo); // ✅ Send updated todo back to frontend
  } catch (error) {
    console.error("❌ Error toggling todo:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});


app.delete('/api/todos/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    console.log("🗑️ Deleting Todo with ID:", id, "for user:", req.user?.userId);

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(id)) {
      console.log("❌ Invalid ObjectId");
      return res.status(400).json({ message: "Invalid Todo ID" });
    }

    const todo = await Todo.findOneAndDelete({ _id: id, userId: req.user?.userId });

    if (!todo) {
      console.log("❌ Todo not found");
      return res.status(404).json({ message: 'Todo not found' });
    }

    console.log("✅ Todo deleted successfully:", id);
    res.json({ message: 'Todo deleted successfully' });
  } catch (error) {
    console.error("❌ Error deleting todo:", error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'API is running' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
