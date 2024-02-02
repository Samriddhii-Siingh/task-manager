const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const User = require("../models/user");

const SECRET_KEY = "ASDFGHJKL1234ZXCVBNM0987QWERTYUIOP456789";

// User registration route
router.post("/register", async (req, res) => {
  try {
    const { phone_number, password } = req.body;

    // Check if a user with the given phone number already exists
    const existingUser = await User.findOne({ phone_number });

    if (existingUser) {
      // User with the given phone number already exists
      return res
        .status(409)
        .json({ error: "User with the given phone number already exists" });
    }

    // Hash the password before saving it to the database
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      phone_number,
      password: hashedPassword,
    });

    const savedUser = await newUser.save();

    res
      .status(201)
      .json({ message: "User registered successfully", user: savedUser });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { phone_number, password } = req.body;

    const user = await User.findOne({ phone_number });

    if (!user) {
      return res.status(401).json({ error: "Invalid user credentials" });
    }

    // Ensure that user.password is not null or undefined before attempting to compare
    if (!user.password) {
      return res
        .status(401)
        .json({ error: "Invalid password" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid password" });
    }

    const token = jwt.sign({ userId: user.id }, SECRET_KEY, {
      expiresIn: "1h",
    });
    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    console.error("Error logging in", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

module.exports = router;
