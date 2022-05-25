const express = require("express")
const router = express.Router()
const { register, login, chats } = require("./auth")
router.route("/register").post(register);
router.route("/login").post(login);

function checkParams(){
    console.log("idkdkdk")
    return true;
}

router.route("/main").post(chats, checkParams);
module.exports = router;














