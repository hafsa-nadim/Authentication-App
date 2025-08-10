require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log(err));

// User model
const User = mongoose.model("User", {
  name: String,
  email: String,
  password: String
});

// Register
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  await User.create({ name, email, password: hash });
  res.send({ message: "User registered" });
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).send({ error: "User not found" });

  const match = await bcrypt.compare(password, user.password);
  if (!match) return res.status(400).send({ error: "Invalid password" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
  res.send({ token });
});

// Profile
app.get("/profile", async (req, res) => {
  const token = req.headers.authorization;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    res.send(user);
  } catch (err) {
    res.status(401).send({ error: "Invalid token" });
  }
});

app.listen(process.env.PORT, () => console.log(`http://localhost${process.env.PORT}`));
