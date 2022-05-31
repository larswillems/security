// user.js
const Mongoose = require("mongoose")
const UserSchema = new Mongoose.Schema({
id: {
    type: Number,
    //unique: true,
    required: true,
    },
  name: {
    type: String,
    //unique: true,
    required: true,
  },
  description: {
    type: String,
    required: true,
    default: '',
  },
  username: {
    type: String,
    required: true,
  },
  private: {
    type: Boolean,
    required: true,
  },
  encrypted: {
    type: Boolean,
    required: true,
  },
  forceMembership: {
    type: Boolean,
    required: true,
    default: false,
  }, 
  members:{
    type: Array,
    required: true
  }
})

const Rooms = Mongoose.model("rooms", UserSchema)
module.exports = Rooms