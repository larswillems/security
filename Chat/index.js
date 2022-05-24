// Setup basic express server
const fs = require('fs');
const hostname = 'localhost';
const express = require('express');
const cookieParser = require("cookie-parser");
const app     = express();
app.use(cookieParser());
const path    = require('path');
const credentials = {
  key: fs.readFileSync('key.pem', 'utf8'),
  cert: fs.readFileSync('cert.pem', 'utf8')
};
const server  = require('https').createServer(credentials, app);
const io      = require('socket.io')(server);
const port    = process.env.PORT || 8443;

const Users   = require('./users.js');
const Rooms   = require('./rooms.js');

const {userAuth} = require("./middleware/auth.js");

app.get("/", (req, res) => res.render("home"))
app.get("/register", (req, res) => res.render("register"))
app.get("/login", (req, res) => res.render("login"))
app.get("/main", userAuth, (req, res) => res.render("main"))

// Load application config/state
require('./basicstate.js').setup(Users,Rooms);

// Start server
server.listen(port, hostname, () => {
  console.log(`Server running at https://${hostname}:${port}/`);
});


// Handling Error
process.on("unhandledRejection", err => {
  console.log(`An error occurred: ${err.message}`)
  //server.close(() => process.exit(1))
})

// Routing for client-side files
app.use(express.static(path.join(__dirname, 'public')));

var bodyParser = require('body-parser');

// configure the app to use bodyParser()
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(bodyParser.json());

//app.use(express.json())
app.use("/api/auth", require("./auth/route"));

app.set("view engine", "ejs")




//////////////////////
// Crypto functions //
//////////////////////

const crypto = require('crypto');

function pbkdf2(password) {
  const salt = crypto.randomBytes(60); 
  let key = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');

  return {key: key, salt: salt};
}

function aesEncrypt (to_encrypt_, key_, iv_) {
  let to_encrypt = Buffer.from(to_encrypt_, 'utf8');
  let key = Buffer.from(key_, 'hex');
  let iv = Buffer.from(iv_, 'hex');

  const cipher = crypto.createCipheriv('aes-256-ctr', key, iv);
  let encrypted = cipher.update(to_encrypt, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  return encrypted;
};

function aesDecrypt (encrypted_, key_, iv_) {
  let encrypted = Buffer.from(encrypted_, 'hex');
  let key = Buffer.from(key_, 'hex');
  let iv = Buffer.from(iv_, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-ctr', key, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
};


///////////////////////////////
// Chatroom helper functions //
///////////////////////////////

function sendToRoom(room, event, data) {
  io.to('room' + room.getId()).emit(event, data);
}

function newUser(name) {
  const user = Users.addUser(name);
  const rooms = Rooms.getForcedRooms();

  rooms.forEach(room => {
    addUserToRoom(user, room);
  });

  return user;
}

function newRoom(name, user, options) {
  const room = Rooms.addRoom(name, options);
  addUserToRoom(user, room);
  return room;
}

function newChannel(name, description, private, user) {
  return newRoom(name, user, {
    description: description,
    private: private
  });
}

function newDirectRoom(user_a, user_b) {
  const room = Rooms.addRoom(`Direct-${user_a.name}-${user_b.name}`, {
    direct: true,
    private: true,
  });

  addUserToRoom(user_a, room);
  addUserToRoom(user_b, room);

  return room;
}

function getDirectRoom(user_a, user_b) {
  const rooms = Rooms.getRooms().filter(r => r.direct 
    && (
      (r.members[0] == user_a.name && r.members[1] == user_b.name) ||
      (r.members[1] == user_a.name && r.members[0] == user_b.name)
    ));

  if (rooms.length == 1)
    return rooms[0];
  else
    return newDirectRoom(user_a, user_b);
}

function addUserToRoom(user, room) {
  user.addSubscription(room);
  room.addMember(user);

  sendToRoom(room, 'update_user', {
    room: room.getId(),
    username: user,
    action: 'added',
    members: room.getMembers()
  });
}

function removeUserFromRoom(user, room) {
  user.removeSubscription(room);
  room.removeMember(user);

  sendToRoom(room, 'update_user', {
    room: room.getId(),
    username: user,
    action: 'removed',
    members: room.getMembers()
  });
}

function addMessageToRoom(roomId, username, msg) {
  const room = Rooms.getRoom(roomId);

  msg.time = new Date().getTime();

  if (room) {
    sendToRoom(room, 'new message', {
      username: msg.username,
      message: msg.message,
      room: msg.room,
      time: msg.time,
      direct: room.direct
    });

    room.addMessage(msg);
  }
}

function setUserActiveState(socket, username, state) {
  const user = Users.getUser(username);

  if (user)
    user.setActiveState(state);
  
  socket.broadcast.emit('user_state_change', {
    username: username,
    active: state
  });
}

///////////////////////////////
// Database helper functions //
///////////////////////////////

const connectDB = require("./db");
connectDB();





var url = "mongodb://localhost:27017/";

function createAccount(username, password){
  MongoClient.connect(url, function(err, db) {
    if (err) throw err;
    var dbo = db.db("database");
    var myobj = { username: username, password: password};
    dbo.collection("users").insertOne(myobj, function(err, res) {
      if (err) throw err;
      console.log("1 document inserted", username, password);
      db.close();
    });
  });
}

function userExists(username){
  MongoClient.connect(url, function(err, db) {
    if (err) throw err;
    var dbo = db.db("database");
    dbo.collection("users").findOne({"username":username}, function(err, result) {
      if (err) throw err;
      console.log(result)
      if (result != null){
        return true
      }
      else {
        db.close();
        return false
      }
    });
  });
}

///////////////////////////
// IO connection handler //
///////////////////////////

const socketmap = {};

io.on('connection', (socket) => {
  let userLoggedIn = false;
  let username = false;

  
  ///////////////////////////////
  // incoming database functions/
  ///////////////////////////////

  socket.on("createAccount", req => {
    var username = req.username;//decrypt(req.username);
    var password = req.password;//decrypt(req.password);
    createAccount(username, password);
  })

  socket.on('simplecall', function(name, fn) {
    // find if "name" exists
    fn({ exists: false });
  });

  socket.on('simplecall2', (callback) => {
    //var exists = userExists(username);
    callback(false);

  });

  socket.on("update item", (arg1, arg2, callback) => {
    console.log(arg1); // 1
    console.log(arg2); // { name: "updated" }
    callback({
      status: "ok"
    });
  });

  socket.on('userExists', (username, callback) => {
    //var exists = userExists(username);
    callback({data:true});

  });


  
  ///////////////////////
  // incomming message //
  ///////////////////////

  socket.on('new message', (msg) => {
    if (userLoggedIn) {
      console.log(msg);

      addMessageToRoom(msg.room, username, msg);
    }
  });

  /////////////////////////////
  // request for direct room //
  /////////////////////////////


  socket.on('request_direct_room', req => {
    if (userLoggedIn) {
      const user_a = Users.getUser(req.to);
      const user_b = Users.getUser(username);

      if(user_a && user_b) {
        const room = getDirectRoom(user_a, user_b);
        const roomCID = 'room' + room.getId();
        socket.join(roomCID);
        if (socketmap[user_a.name])
         socketmap[user_a.name].join(roomCID);

        socket.emit('update_room', {
          room: room,
          moveto: true
        });
      }
    }
  });

  socket.on("create_db", req => {
    console.log(req.user)
  })

  socket.on('add_channel', req => {
    if (userLoggedIn) {
      const user = Users.getUser(username);
      console.log(req);
      const room = newChannel(req.name, req.description, req.private, user);
      const roomCID = 'room' + room.getId();
      socket.join(roomCID);

      socket.emit('update_room', {
        room: room,
        moveto: true
      });

      if (!room.private) {
        const publicChannels = Rooms.getRooms().filter(r => !r.direct && !r.private);
        socket.broadcast.emit('update_public_channels', {
          publicChannels: publicChannels
        });
      }
    }
  });

  socket.on('join_channel', req => {
    if (userLoggedIn) {
      const user = Users.getUser(username);
      const room = Rooms.getRoom(req.id)

      if(!room.direct && !room.private) {
        addUserToRoom(user, room);
        
        const roomCID = 'room' + room.getId();
        socket.join(roomCID);

        socket.emit('update_room', {
          room: room,
          moveto: true
        });
      }
    }
  });

  
  socket.on('add_user_to_channel', req => {
    if (userLoggedIn) {
      const user = Users.getUser(req.user);
      const room = Rooms.getRoom(req.channel)

      if(!room.direct) {
        addUserToRoom(user, room);
        
        if (socketmap[user.name]) {
          const roomCID = 'room' + room.getId();
          socketmap[user.name].join(roomCID);

          socketmap[user.name].emit('update_room', {
            room: room,
            moveto: false
          });
        }
      }
    }
  });

  socket.on('leave_channel', req => {
    if (userLoggedIn) {
      const user = Users.getUser(username);
      const room = Rooms.getRoom(req.id)

      if(!room.direct && !room.forceMembership) {
        removeUserFromRoom(user, room);
        
        const roomCID = 'room' + room.getId();
        socket.leave(roomCID);

        socket.emit('remove_room', {
          room: room.getId()
        });
      }
    }
  });

  ///////////////
  // user join //
  ///////////////

  socket.on('join', (p_username) => {
    if (userLoggedIn) 
      return;

    username = p_username;
    userLoggedIn = true;
    socketmap[username] = socket;

    const user = Users.getUser(username) || newUser(username);
    
    const rooms = user.getSubscriptions().map(s => {
      socket.join('room' + s);
      return Rooms.getRoom(s);
    });

    const publicChannels = Rooms.getRooms().filter(r => !r.direct && !r.private);

    socket.emit('login', {
      users: Users.getUsers().map(u => ({username: u.name, active: u.active})),
      rooms : rooms,
      publicChannels: publicChannels
    });

    setUserActiveState(socket, username, true);
  });

  /////////////////
  // disconnects //
  /////////////////

  socket.on('disconnect', () => {
    if (userLoggedIn)
      setUserActiveState(socket, username, false);
  });

  ////////////////
  // reconnects //
  ////////////////

  socket.on('reconnect', () => {
    if (userLoggedIn)
      setUserActiveState(socket, username, true);
  });

});
