const mongoose = require("mongoose");

const mediaSchema = new mongoose.Schema({
  url: String,
  type: String,
  uploadedBy: String
}, { timestamps: true });

module.exports = mongoose.model("Media", mediaSchema);
