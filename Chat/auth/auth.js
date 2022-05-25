const User = require("../user")
const jwt = require('jsonwebtoken')

const jwtSecret = "2626c90f1b310c1d98a1ce7bbd6bb09ab5c56e3055b087c0a0cf920820905c79c3d8bd";
// auth.js
exports.register = async (req, res, next) => {
    console.log(req.body);
    const { username, password } = req.body
    if (password.length < 8) {
      return res.status(400).json({ message: "Password less than 8 characters" })
    }
    try {
      await User.create({
        username,
        password,
      }).then((user) => {
        const maxAge = 3 * 60 * 60;
        const token = jwt.sign(
          { id: user._id, username},
          jwtSecret,
          {
            expiresIn: maxAge, // 3hrs in sec
          }
        );
        res.cookie("username", username, {httpOnly:false});
        res.cookie("username_hidden", cyrb53(username), {httpOnly:true});
        res.cookie("jwt", token, {
          httpOnly: true,
          maxAge: maxAge * 1000, // 3hrs in ms
        });
        res.status(201).json({
          message: "User successfully created",
          user: user._id,
        });console.log(res.cookie);
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

exports.login = async (req, res, next) => {
    console.log("reached login");
    try {
      const { username, password } = req.body
      const user = await User.findOne({ username, password })
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
          res.cookie("username", username, {httpOnly:false});
          res.cookie("username_hidden", cyrb53(username), {httpOnly:true});
          res.cookie("jwt", token, {
            httpOnly: true,
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