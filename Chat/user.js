// user.js
const Mongoose = require("mongoose")
const UserSchema = new Mongoose.Schema({
  username: {
    type: String,
    unique: true,
    required: true,
  },
  password: {
    type: String,
    minlength: 8,
    maxlength: 256,
    required: true,
  },
  publicKey: {
    type: String,
    required: true,
  },
  publicKey: {
    type: String,
    required: true,
  },
  seed: {
    type: String,
    required: true,
  },
})

const User = Mongoose.model("user", UserSchema)
module.exports = User