const express = require("express")
const router = express.Router()
const { register, login, chats } = require("./auth")
router.route("/register").post(register);
router.route("/login").post(login);
router.route("/main").post(chats);
module.exports = router;














