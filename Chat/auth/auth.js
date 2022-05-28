const User = require("../user")
const jwt = require('jsonwebtoken')
const crypto = require('crypto')

function generateSalt(){
  const buf = crypto.randomBytes(16);
  return buf
}

function hash(password, salt) {
  let key = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
  return key;
}


const jwtSecret = "2626c90f1b310c1d98a1ce7bbd6bb09ab5c56e3055b087c0a0cf920820905c79c3d8bd";
// auth.js
exports.register = async (req, res, next) => {
    console.log(req.body);
    const { username, password } = req.body
    if (password.length < 8) {
      return res.status(400).json({ message: "Password less than 8 characters" })
    }
    try {
      var salt = generateSalt(); 
      var hashedPassword = hash(password, salt).toString();
      var publicKey = "ok";

      await User.create({
        "username":username,
        "password":hashedPassword,
        "publicKey":publicKey,
        "seed": salt.toString()
      }).then((user) => {
        const maxAge = 3 * 60 * 60;
        const token = jwt.sign(
          { id: user._id, username},
          jwtSecret,
          {
            expiresIn: maxAge, // 3hrs in sec
          }
        );
        var hashed_username = hash(username, salt.toString())

        res.cookie("username", username.toString(), {httpOnly:false, secure:true, maxAge: maxAge * 1000});
        res.cookie("username_hidden", hashed_username.toString(), {httpOnly:true, secure:true, maxAge: maxAge * 1000});
        res.cookie("jwt", token, {
          httpOnly: true, 
          secure:true,
          maxAge: maxAge * 1000, // 3hrs in ms
        });
        res.status(201).json({
          message: "User successfully created",
          user: user._id,
        });
      })
    } catch (err) {
        console.log(err.message)
      res.status(401).json({
        message: "User not successful created",
        error: err.message,
      })
    }
}



// auth.js
exports.login = async (req, res, next) => {
    const { username, password } = req.body
    // Check if username and password is provided
    if (!username || !password) {
      return res.status(400).json({
        message: "Username or Password not present",
      })
    }
  }

async function getSalt(username){
  var salt = null
  try {
    const document = await User.find({"username":username}).then((user) => {
      salt = user[0].seed
    })    
  }
  finally {
      return salt
  }
  
}

async function getPublicKey(username){
  var publicKey = null 
  try {
    const document = await User.find({"username":username}).then((user) => {
      publicKey = user[0].publicKey
    })
  }
  finally {
    return publicKey
  }
  
}

exports.login = async (req, res, next) => {
    try {
      const { username, password } = req.body

      var toType = function(obj) {
        return ({}).toString.call(obj).match(/\s([a-zA-Z]+)/)[1].toLowerCase()
      }

      const buff = crypto.randomBytes(16);


      var salt = await getSalt(username);
      var originalSalt = salt
      salt = Buffer.from(salt, 'utf8'); // string to buffer
      var hashedPassword = hash(password, salt);
      var publicKey = await getPublicKey(username);
            

      const user = await User.findOne({ username, hashedPassword, publicKey, originalSalt })
      if (!user) {
        res.status(401).json({
          message: "Login not successful",
          error: "User not found",
        })
      } else {
        const maxAge = 3 * 60 * 60;
          const token = jwt.sign(
            { id: user._id, username},
            jwtSecret,
            {
              expiresIn: maxAge, // 3 hours in sec
            }
          );
          var hashed_username = hash(username, salt.toString())
          res.cookie("username", username.toString(), {httpOnly:false, secure:true, maxAge: maxAge * 1000});
          res.cookie("username_hidden", hashed_username.toString(), {httpOnly:true, secure:true, maxAge: maxAge * 1000});
          res.cookie("jwt", token, {
            httpOnly: true,
            secure:true,
            maxAge: maxAge * 1000, // 3 hours in ms
          });
          res.status(201).json({
            message: "User successfully Logged in",
            user: user._id,
          });
      }
    } catch (error) {
      res.status(400).json({
        message: "An error occurred",
        error: error.message,
      })
    }
}


exports.chats = async (req, res, next) => {
  try {
    const { username} = req.body
    const user = await User.findOne({ username})
    if (!user) {
      res.status(401).json({
        message: "Login not successful",
        error: "User not found",
      })
    } else {
      const maxAge = 3 * 60 * 60;
        const token = jwt.sign(
          { id: user._id, username},
          jwtSecret,
          {
            expiresIn: maxAge, // 3 hours in sec
          }
        );
        res.cookie("jwt", token, {
          httpOnly: true,
          secure:true,
          maxAge: maxAge * 1000, // 3 hours in ms
        });
        res.status(201).json({
          message: "User successfully Logged in",
          user: user._id,
        });
    }
  } catch (error) {
    res.status(400).json({
      message: "An error occurred",
      error: error.message,
    })
  }
}