// user.js
const Mongoose = require("mongoose")
const UserSchema = new Mongoose.Schema({
  roomId: {
    type: Number,
    required: true,
  },
  username: {
    type: String,
    required: true,
  },
  message: {
    type: String,
    required: true,
  },
  time: {
    type: Number,
    required: true,
  },
  authentication: {
    type: String,
    default:'',
  },
  keyArray: {
    type: Array,
    required: true,
  },
})

const Messages = Mongoose.model("messages", UserSchema)
module.exports = Messages