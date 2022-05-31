const jwt = require("jsonwebtoken")
const User = require("../user")


const jwtSecret = "2626c90f1b310c1d98a1ce7bbd6bb09ab5c56e3055b087c0a0cf920820905c79c3d8bd"

exports.adminAuth = (req, res, next) => {
  const token = req.cookies.jwt
  if (token) {
    jwt.verify(token, jwtSecret, (err, decodedToken) => {
      if (err) {
        return res.status(401).json({ message: "Not authorized" })
      } else {
        if (decodedToken.role !== "admin") {
          return res.status(401).json({ message: "Not authorized" })
        } else {
          next()
        }
      }
    })
  } else {
    return res
      .status(401)
      .json({ message: "Not authorized, token not available" })
  }
}

const crypto = require('crypto')

function hash(password, salt) {
  let key = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
  return key;
}


async function getSalt(username){
  var salt = null
  try {
    console.log("fucket")
    const document = await User.find({"username":username}).then((user) => {
      console.log(user)
      salt = user[0].seed
    })    
  } catch (e){
    console.log(e)
  }
  finally {
      return salt
  }
  
}

exports.userAuth = async (req, res, next) => {
    const token = req.cookies.jwt
    const username = req.cookies.username.toString()
    const username_hidden = req.cookies.username_hidden
    var salt = await getSalt(username);
    //salt = Buffer.from(salt, 'utf8'); // string to buffer
    console.log("string salt", salt)

    var hashed_username = hash(username, salt).toString();

    console.log("userauth", username, salt, hashed_username, hashed_username.toString())
    if(username==null){
      return res
        .status(401)
        .json("Not authorized. Please login.")
    }

    if (token) {
      jwt.verify(token, jwtSecret, (err, decodedToken) => {
        if (err) {
          return res.status(401).json({ message: "Not authorized" })
        } else {
          if (hashed_username == username_hidden){
            next()
          }
          else {
            return res.status(401).json({ message: "Not authorized for this user" })
          }
        }
      })
    } else {
      return res
        .status(401)
        .json({ message: "Not authorized, token not available" })
    }
  }