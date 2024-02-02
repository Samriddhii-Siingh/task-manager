const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  phone_number: {
    type: Number,
    required: true,
  },
  password: {
    type: String,
    required: true,
  }
});

const User = mongoose.model("User", userSchema);
module.exports = User;
