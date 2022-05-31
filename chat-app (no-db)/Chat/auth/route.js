const express = require("express")
const router = express.Router()
const { register, login, chats } = require("./auth")
router.route("/register").post(register);
router.route("/login").post(login);

function checkParams(){
    return true;
}

router.route("/main").post(chats, checkParams);
module.exports = router;














