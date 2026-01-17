const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema({
  from: String,
  to: String,
  text: String
}, { timestamps: true });

module.exports = mongoose.model("Message", messageSchema);
