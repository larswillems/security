$(function() {
  // Initialize variables
  const $window = $(window);
  const $messages      = $('.messages'); // Messages area
  const $inputMessage  = $('#input-message'); // Input message input box
  const $usernameLabel = $('#user-name');
  const $userList      = $('#user-list');
  const $roomList      = $('#room-list');

  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  }

  username = getCookie("username");
  $usernameLabel.text(username); 
  console.log(username);

  // Prompt for setting a username
  //TODO: replace(/</g, "&lt;").replace(/>/g, "&gt;");
  //let username = prompt("Enter your username:").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  //$usernameLabel.text(username);

  let connected = false;
  let socket = io();
  let modalShowing = false;

  $('#addChannelModal').on('hidden.bs.modal', () => modalShowing = false)
                        .on('show.bs.modal',   () => modalShowing = true);



  //////////////////////
  // Encryption: HMAC //
  //////////////////////

  let aes_Key = "12345678901234567890123456789012"; // for AES encryption (16 byte key)
  let hmac_Key = "password"; // for HMAC authentication

  // HMAC
  function hmac(ciphertext, iv, passphrase, salt) {
    // parse salt
    let PBKDF2_salt = CryptoJS.enc.Hex.parse(salt);

    // apply PBKDF2 salt to passphrase
    let PBKDF2_passphrase = CryptoJS.PBKDF2(passphrase, PBKDF2_salt, {
      keySize: 128 / 32,
      iterations: 1024
    });

    // create hmac hash
    let hash = CryptoJS.HmacSHA512(iv + ciphertext, PBKDF2_passphrase);

    return {hash: hash, salt: PBKDF2_salt};
  }


  /////////////////////
  // Encryption: RSA //
  /////////////////////

  // Generate RSA keys
  async function generateRSAkeys() {
    let keys = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 4096,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      false, // "exctratable" is set to false, meaning key cannot be exported or read.
      ["encrypt", "decrypt"]
    );
    return keys;
  }

  // RSA Encryption
  function rsaEncrypt(data, keys) {
    return window.crypto.subtle.encrypt(
      {name: "RSA-OAEP",},
      keys.publicKey,
      data
    )
  }

  // RSA Decryption
  async function rsaDecrypt(data, keys) {
    return new Uint8Array(await window.crypto.subtle.decrypt(
        {name: "RSA-OAEP",},
        keys.privateKey,
        data
    ));
  }

  // test
  async function encryptDecrypt() {
    var data = new TextEncoder().encode("hello");
    console.log("generated data", data);
    var keys = await generateRSAkeys();
    var encrypted = await rsaEncrypt(data, keys);
    console.log("encrypted", encrypted);
    var finalData = new TextDecoder("utf-8").decode(await rsaDecrypt(encrypted, keys));
    console.log("decrypted data", finalData);
  }
  console.log(encryptDecrypt());


  /////////////////////
  // Encryption: AES //
  /////////////////////

  // Generate AES key
  function generateAESkey() {
    return CryptoJS.lib.WordArray.random(32);
  }

  // AES-CTR encryption
  function aesEncrypt(msg, key) {
    let key_parsed = CryptoJS.enc.Hex.parse(key);
    let iv_parsed = CryptoJS.lib.WordArray.random(16);

    let encryption = CryptoJS.AES.encrypt(msg, key_parsed, {
      mode: CryptoJS.mode.CTR,
      iv: iv_parsed,
      padding: CryptoJS.pad.NoPadding
    });
    
    // the encrypted message is a concatenation of the IV, ciphertext, HMAC hash and HMAC salt:
    let iv = iv_parsed.toString();
    let ciphertext = encryption.toString();
    let hmac_salt = CryptoJS.lib.WordArray.random(16).toString();
    let hmac_str = hmac(ciphertext, iv, hmac_Key, hmac_salt).hash.toString();
    let encrypted_msg = iv + ciphertext + hmac_str + hmac_salt;

    return encrypted_msg;
  }

  // AES-CTR decryption
  function aesDecrypt(encrypted, key, iv) {
    let encrypted_parsed = CryptoJS.enc.Base64.parse(encrypted);
    let key_parsed = CryptoJS.enc.Hex.parse(key);
    let iv_parsed = CryptoJS.enc.Hex.parse(iv);

    let aesDecryptor = CryptoJS.algo.AES.createDecryptor(key_parsed, {
      mode: CryptoJS.mode.CTR,
      iv: iv_parsed,
      padding: CryptoJS.pad.NoPadding
    });

    let decrypted = aesDecryptor.process(encrypted_parsed);
    decrypted += aesDecryptor.finalize();

    let decrypted_parsed = CryptoJS.enc.Hex.parse(decrypted);
    let decrypted_utf8 = decrypted_parsed.toString(CryptoJS.enc.Utf8);

    return decrypted_utf8;
  }


  ///////////////
  // User List //
  ///////////////

  let users = {};

  function updateUsers(p_users) {
    p_users.forEach(u => users[u.username] = u);
    updateUserList();
  }

  function updateUser(username, active) {
    if (!users[username])
      users[username] = {username: username};

    users[username].active = active;

    updateUserList();
  }

  function updateUserList() {
    const $uta = $("#usersToAdd");
    $uta.empty();

    $userList.empty();
    for (let [un, user] of Object.entries(users)) {
      if (username !== user.username)
        $userList.append(`
          <li onclick="setDirectRoom(this)" data-direct="${user.username}" class="${user.active ? "online" : "offline"}">${user.username}</li>
        `);
        // append it also to the add user list
        $uta.append(`
          <button type="button" class="list-group-item list-group-item-action" data-dismiss="modal" onclick="addToChannel('${user.username}')">${user.username}</button>
        `); 
    };
  }

  ///////////////
  // Room List //
  ///////////////

  let rooms = [];

  function updateRooms(p_rooms) {
    rooms = p_rooms;
    updateRoomList();
  }

  function updateRoom(room) {
    rooms[room.id] = room;
    updateRoomList();
  }

  function removeRoom(id) {
    delete rooms[id];
    updateRoomList();
  }

  function updateRoomList() {
    $roomList.empty();
    rooms.forEach(r => {
      if (!r.direct)
        $roomList.append(`
          <li onclick="setRoom(${r.id})"  data-room="${r.id}" class="${r.private ? "private" : "public"}">${r.name}</li>
        `);
    });
  }


  function updateChannels(channels) {
    const c = $("#channelJoins");

    c.empty();
    channels.forEach(r => {
      if (!rooms[r.id]) 
        c.append(`
          <button type="button" class="list-group-item list-group-item-action" data-dismiss="modal" onclick="joinChannel(${r.id})">${r.name}</button>
        `); 
    });
  }


  //////////////
  // Chatting //
  //////////////

  let currentRoom = false;

  function setRoom(id) {
    let oldRoom = currentRoom;

    const room = rooms[id];
    currentRoom = room;

    $messages.empty();
    room.history.forEach(m => addChatMessage(decryptProcessedMsg(m, processEncryptedMsg(m))));

    $userList.find('li').removeClass("active");
    $roomList.find('li').removeClass("active");

    if (room.direct) {
      const idx = room.members.indexOf(username) == 0 ? 1 : 0;
      const user = room.members[idx];
      setDirectRoomHeader(user);

      $userList.find(`li[data-direct="${user}"]`)
        .addClass("active")
        .removeClass("unread")
        .attr('data-room', room.id);

    } else {
      $('#channel-name').text("#" + room.name);
      $('#channel-description').text(`👤 ${room.members.length} | ${room.description}`);
      $roomList.find(`li[data-room=${room.id}]`).addClass("active").removeClass("unread");
    }

    $('.roomAction').css('visibility', (room.direct || room.forceMembership) ? "hidden" : "visible");
  }
  window.setRoom = setRoom;

  function setDirectRoomHeader(user) {
    $('#channel-name').text(user);
    $('#channel-description').text(`Direct message with ${user}`);
  }

  function setToDirectRoom(user) {
    setDirectRoomHeader(user);
    socket.emit('request_direct_room', {to: user});
  }

  window.setDirectRoom = (el) => {
    const user = el.getAttribute("data-direct");
    const room = el.getAttribute("data-room");

    if (room) {
      setRoom(parseInt(room));
    } else {
      setToDirectRoom(user);
    }
  }

  function sendMessage() {
    // retrieve input and sanitize against XSS attacks
    let input = $inputMessage.val().replace(/</g, "&lt;").replace(/>/g, "&gt;");

    // encrypt sanitized input:
    let encrypted_message = aesEncrypt(input, aes_Key);
    let encrypted_username = aesEncrypt(username, aes_Key);

    if (encrypted_message && connected && currentRoom !== false) {
      $inputMessage.val('');
      const msg = {username: encrypted_username, message: encrypted_message, room: currentRoom.id};
      
      //addChatMessage(msg);
      socket.emit('new message', msg);
    }
  }


  function processEncryptedMsg(msg) {
    let authentication = "";

    // extract IV, HMAC, and ciphertext from message and username
    let message_iv = msg.message.slice(0,32);
    let message_hmac_salt_received = msg.message.slice(msg.message.length-32, msg.message.length);
    let message_hmac_hash_received = msg.message.slice(msg.message.length-32-128, msg.message.length-32);
    let message_ciphertext = msg.message.slice(32, msg.message.length-32-128);

    let username_iv = msg.username.slice(0,32);
    let username_hmac_salt_received = msg.username.slice(msg.username.length-32, msg.username.length);
    let username_hmac_hash_received = msg.username.slice(msg.username.length-32-128, msg.username.length-32);
    let username_ciphertext = msg.username.slice(32, msg.username.length-32-128);

    // check HMACs
    let message_hmac_hash_match = hmac(message_ciphertext, message_iv, hmac_Key, message_hmac_salt_received).hash.toString();
    let username_hmac_hash_match = hmac(username_ciphertext, username_iv, hmac_Key, username_hmac_salt_received).hash.toString();

    if (message_hmac_hash_match == message_hmac_hash_received && username_hmac_hash_match == username_hmac_hash_received) {
      authentication = "🟢"; // authenticated.
    } else {
      authentication = "🔴"; // not authenticated.
    }

    let processed_msg = {message_ciphertext: message_ciphertext, username_ciphertext: username_ciphertext, 
            message_iv: message_iv, username_iv: username_iv, 
            authentication: authentication};

    return processed_msg;
  }

  function decryptProcessedMsg(msg, processed_msg) {
    // decrypt message and username
    msg.message = aesDecrypt(processed_msg.message_ciphertext, aes_Key, processed_msg.message_iv);
    msg.username = aesDecrypt(processed_msg.username_ciphertext, aes_Key, processed_msg.username_iv);
    msg.authentication = processed_msg.authentication;
    return msg;
  }

  function addChatMessage(msg) {
    // display time and message
    let time = new Date(msg.time).toLocaleTimeString('en-US', { hour12: false, 
                                                        hour  : "numeric", 
                                                        minute: "numeric"});

    $messages.append(`
      <div class="message">
        <div class="message-avatar"></div>
        <div class="message-textual">
          <span class="message-user">${msg.username}</span>
          <span class="message-authentication" title="Authentication Status">${msg.authentication}</span>
          <span class="message-time">${"(" + time + ")"}</span>
          <span class="message-content">${msg.message}</span>
        </div>
      </div>
    `);

    $messages[0].scrollTop = $messages[0].scrollHeight;
  }

  function messageNotify(msg) {
    if (msg.direct)
      $userList.find(`li[data-direct="${msg.username}"]`).addClass('unread');
    else
      $roomList.find(`li[data-room=${msg.room}]`).addClass("unread");
  }


  function addChannel() {
    // retrieve inputs and sanitize against XSS attacks
    const name = $("#inp-channel-name").val().replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const description = $("#inp-channel-description").val().replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const private = $('#inp-private').is(':checked');

    socket.emit('add_channel', {name: name, description: description, private: private});
  }
  window.addChannel = addChannel;


  function joinChannel(id) {
    socket.emit('join_channel', {id: id});
  }
  window.joinChannel = joinChannel;

  function addToChannel(user) {
    socket.emit('add_user_to_channel', {channel: currentRoom.id, user: user});   
  }
  window.addToChannel = addToChannel;

  function leaveChannel() {
    socket.emit('leave_channel', {id: currentRoom.id});   
  }
  window.leaveChannel = leaveChannel;

  /////////////////////
  // Keyboard events //
  /////////////////////

  $window.keydown(event => {
    if(modalShowing)
      return;
    
    // Autofocus the current input when a key is typed
    if (!(event.ctrlKey || event.metaKey || event.altKey)) {
      $inputMessage.focus();
    }

    // When the client hits ENTER on their keyboard
    if (event.which === 13) {
      console.log('enter');
      sendMessage();
    }

    // don't add newlines
    if (event.which === 13 || event.which === 10) {
      event.preventDefault();
    }
  });



  ///////////////////
  // server events //
  ///////////////////

  // Whenever the server emits -login-, log the login message
  socket.on('login', (data) => {
    connected = true;

    updateUsers(data.users);
    updateRooms(data.rooms);
    updateChannels(data.publicChannels);

    if (data.rooms.length > 0) {
      setRoom(data.rooms[0].id);
    }
  });

  socket.on('update_public_channels', (data) => {
    updateChannels(data.publicChannels);
  });

  // Whenever the server emits 'new message', update the chat body
  socket.on('new message', (encrypted_msg) => {
    // decrypt message
    let msg = decryptProcessedMsg(encrypted_msg, processEncryptedMsg(encrypted_msg));

    // add message
    const roomId = msg.room;
    const room = rooms[roomId];

    if (room) {
      room.history.push(msg);
    }

    if (roomId == currentRoom.id)
      addChatMessage(msg);
    else
      messageNotify(msg);
  });

  socket.on('update_user', data => {
    const room = rooms[data.room];
    if (room) {
      room.members = data.members;
      
      if (room === currentRoom)
        setRoom(data.room);
    }
  });

  socket.on('user_state_change', (data) => {
    updateUser(data.username, data.active);
  });

  socket.on('update_room', data => {
    updateRoom(data.room);
    if (data.moveto)
      setRoom(data.room.id);
  });

  socket.on('remove_room', data => {
    removeRoom(data.room);
    if (currentRoom.id == data.room)
      setRoom(0);
  });

  ////////////////
  // Connection //
  ////////////////

  socket.on('connect', () => {
    socket.emit('join', username)
  });

  socket.on('disconnect', () => {
  });

  socket.on('reconnect', () => {
    // join
    socket.emit('join', username);
  });

  socket.on('reconnect_error', () => {
  });

});
