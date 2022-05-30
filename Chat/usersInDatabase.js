// user.js
const Mongoose = require("mongoose")
const UserSchema = new Mongoose.Schema({
  id: {type:Number},
  roomId: {
    type: Number,
    unique: true,
    required: true,
    },
  username: {
    type: String,
    required: true,
  },
  added: {
      type: Boolean,
      required: true
  }
})

const usersInDatabase = Mongoose.model("usersInDatabase", UserSchema)
module.exports = usersInDatabase