const mongoose = require("mongoose");

const MediaSchema = new mongoose.Schema({
  url: String,
  type: String,
  uploadedBy: String,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Media", MediaSchema);
