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
const cyrb53 = function(str, seed = 0) {
  let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
  for (let i = 0, ch; i < str.length; i++) {
      ch = str.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1>>>16), 2246822507) ^ Math.imul(h2 ^ (h2>>>13), 3266489909);
  h2 = Math.imul(h2 ^ (h2>>>16), 2246822507) ^ Math.imul(h1 ^ (h1>>>13), 3266489909);
  return 4294967296 * (2097151 & h2) + (h1>>>0);
};

// auth.js
exports.register = async (req, res, next) => {
    const { username, password, publicKey } = req.body
    if (password.length < 8 || password.length > 30 || username.length < 1 || username.length > 30) {
      return res.status(400).json({ message: "Invalid input. Username should be between 1 and 30 characters long. Password should be at least 8 characters long." })
    }
    try {
      var salt = generateSalt(); 
      var hashedPassword = hash(password, salt).toString();

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

        res.cookie("username", username.toString(), {httpOnly:false, sameSite: true, secure: true, maxAge: maxAge * 1000});
        res.cookie("username_hidden", hashed_username.toString(), {httpOnly:true, sameSite: true, secure: true, maxAge: maxAge * 1000});
        res.cookie("jwt", token, {
          httpOnly: true, 
          secure: true,
          sameSite: true,
          maxAge: maxAge * 1000, // 3hrs in ms
        });
        res.status(201).json({
          message: "User successfully created",
          user: user._id,
        });
      })
    } catch (err) {
      res.status(401).json({
        message: "User not successful created",
        error: err.message,
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
          res.cookie("username", username.toString(), {httpOnly:false, sameSite: true, secure: true, maxAge: maxAge * 1000});
          res.cookie("username_hidden", hashed_username.toString(), {httpOnly:true, sameSite: true, secure: true, maxAge: maxAge * 1000});
          res.cookie("jwt", token, {
            httpOnly: true,
            secure: true,
            sameSite: true,
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
// auth.js
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
          secure: true,
          sameSite: true,
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