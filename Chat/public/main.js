$(function() {
  // Initialize variables
  const $window = $(window);
  const $messages      = $('.messages'); // Messages area
  const $inputMessage  = $('#input-message'); // Input message input box
  const $usernameLabel = $('#user-name');
  const $userList      = $('#user-list');
  const $roomList      = $('#room-list');
  var publicKey = null;

  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
  }

  username = getCookie("username");
  $usernameLabel.text(username); 

  let connected = false;
  let socket = io();
  let modalShowing = false;

  $('#addChannelModal').on('hidden.bs.modal', () => modalShowing = false)
                        .on('show.bs.modal',   () => modalShowing = true);



  //////////////////////
  // Encryption: HMAC //
  //////////////////////

  // HMAC
  function hmac(ciphertext, iv, passphrase, salt) {
    // parse salt
    let pbkdf2_salt = CryptoJS.enc.Hex.parse(salt);

    // apply PBKDF2 salt to passphrase
    let pbkdf2_passphrase = CryptoJS.PBKDF2(passphrase, pbkdf2_salt, {
      keySize: 128 / 32,
      iterations: 1024
    });

    // create hmac hash
    let hash = CryptoJS.HmacSHA512(iv + ciphertext, pbkdf2_passphrase);

    return {hash: hash, salt: pbkdf2_salt};
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
      false, // "extractable" is set to false, meaning key cannot be exported or read.
      ["encrypt", "decrypt"]
    );
    return keys;
  }

  // RSA Encryption
  function rsaEncrypt(data, publicKey) {
    return window.crypto.subtle.encrypt(
      {name: "RSA-OAEP",},
      publicKey,
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

  // RSA Export publicKey
  async function exportCryptoKey(publicKey) {
    const exported = await window.crypto.subtle.exportKey(
      "jwk",
      publicKey
    );
    return exported;
  }

  // RSA Import publicKey
  async function importCryptoKey(jwk_publicKey) {
    return await window.crypto.subtle.importKey(
      "jwk",
      jwk_publicKey,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["encrypt"]
    );
  }


  ///////////////////
  // Local Storage //
  ///////////////////

  function callOnStore(fn_) { 
    // Open (or create) the local database
    var indexedDB = window.indexedDB || window.mozIndexedDB || window.webkitIndexedDB || window.msIndexedDB || window.shimIndexedDB;
    var open = indexedDB.open("MyLocalDatabase", 1);

    open.onupgradeneeded = function() {
        var db = open.result;
        // Create an store object for this database
        var store = db.createObjectStore("MyObjectStore", {keyPath: "id"});
    };

    open.onsuccess = function() {
        // Start a new transaction
        var db = open.result;
        var tx = db.transaction("MyObjectStore", "readwrite");
        var store = tx.objectStore("MyObjectStore");

        fn_(store)
        // Close the db when the transaction is done
        tx.oncomplete = function() {
            db.close();
        };
    }
  }


  /////////////////////
  // Encryption: AES //
  /////////////////////

  // AES-CTR encryption
  function aesEncrypt(message, username) {
    let aes_Key = CryptoJS.lib.WordArray.random(32);
    let hmac_Key = CryptoJS.SHA256(aes_Key.toString());
    let iv_message = CryptoJS.lib.WordArray.random(16);
    let iv_username = CryptoJS.lib.WordArray.random(16);
    while (iv_message==iv_username) {iv_username = CryptoJS.lib.WordArray.random(16);}

    // encrypt message
    let encryption_message = CryptoJS.AES.encrypt(message, aes_Key, {
      mode: CryptoJS.mode.CTR,
      iv: iv_message,
      padding: CryptoJS.pad.NoPadding
    });
    
    // encrypt username
    let encryption_username = CryptoJS.AES.encrypt(username, aes_Key, {
      mode: CryptoJS.mode.CTR,
      iv: iv_username,
      padding: CryptoJS.pad.NoPadding
    });

    // the encrypted message is a concatenation of the IV, ciphertext, HMAC hash and HMAC salt:
    let iv_m = iv_message.toString();
    let ciphertext_m = encryption_message.toString();
    let hmac_salt_m = CryptoJS.lib.WordArray.random(16).toString();
    let hmac_str_m = hmac(ciphertext_m, iv_m, hmac_Key, hmac_salt_m).hash.toString();
    let encrypted_message = iv_m + ciphertext_m + hmac_str_m + hmac_salt_m;

    let iv_u = iv_username.toString();
    let ciphertext_u = encryption_username.toString();
    let hmac_salt_u = CryptoJS.lib.WordArray.random(16).toString();
    let hmac_str_u = hmac(ciphertext_u, iv_u, hmac_Key, hmac_salt_u).hash.toString();
    let encrypted_username = iv_u + ciphertext_u + hmac_str_u + hmac_salt_u;

    return {encrypted_message: encrypted_message, encrypted_username: encrypted_username, key: aes_Key};
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

  let users = [];

  function updateUsers(p_users) {
    p_users.forEach(u => users.push(u));
    uniq = [...new Set(users)];
    users = uniq;
    updateUserList();
  }

  function updateUser(user_data) {
    var found = false;
    for (const u of users) {
      if (u.username == user_data.name) {
        found = true;
        users[users.indexOf(u)].active = user_data.active;
      }
    }
    if (!found)
      users.push({username: user_data.name, active: user_data.active, publicKey: user_data.publicKey})

    updateUserList();
  }

  function updateUserList() {
    const $uta = $("#usersToAdd");
    $uta.empty();

    $userList.empty();
    for (let [un, user] of Object.entries(users)) {
      if (username !== user.username) {
        $userList.append(`
          <li 
          onclick="setDirectRoom(this)" 
          data-direct="${user.username.replace(/</g, "&lt;").replace(/>/g, "&gt;")}" 
          class="${user.active ? "online" : "offline"}">
            ${user.username.replace(/</g, "&lt;").replace(/>/g, "&gt;")}
          </li>
        `);
        // append it also to the add user list
        $uta.append(`
          <button 
            type="button" 
            class="list-group-item list-group-item-action" 
            data-dismiss="modal" 
            onclick="addToChannel('${user.username.replace(/</g, "&lt;").replace(/>/g, "&gt;")}')">
              ${user.username.replace(/</g, "&lt;").replace(/>/g, "&gt;")}
            </button>
        `); 
      }
    };
  }

  ///////////////
  // Room List //
  ///////////////

  let rooms = [];

  function updateRooms(p_rooms) {
    rooms = p_rooms;
  }

  function updateRoom(room) {
    var found = false;
    for (const r of rooms) {
      if (r.id == room.id) {
        found = true;
        rooms[rooms.indexOf(r)] = room;
      }
    }
    if (!found)
      rooms.push(room)

    updateRoomList();
  }

  function removeRoom(id) {
    for (const r of rooms) {
      found = true;
      if (r.id == room.id) {
        delete rooms[rooms.indexOf(r)];
      }
    }
    updateRoomList();
  }

  function updateRoomList() {
    $roomList.empty();
    rooms.forEach(r => {
      if (!r.direct)
        $roomList.append(`
          <li 
            onclick="setRoom(${r.id})"  
            data-room="${r.id}" 
            class="${r.private ? "private" : "public"}">
              ${r.name.replace(/</g, "&lt;").replace(/>/g, "&gt;")}
            </li>
        `);
    });
  }


  function updateChannels(channels) {
    const c = $("#channelJoins");

    c.empty();
    channels.forEach(r => {
      if (!rooms[r.id]) 
        c.append(`
          <button 
            type="button" 
            class="list-group-item list-group-item-action" 
            data-dismiss="modal" 
            onclick="joinChannel(${r.id})">
              ${r.name.replace(/</g, "&lt;").replace(/>/g, "&gt;")}
            </button>
        `); 
    });
  }


  //////////////
  // Chatting //
  //////////////

  let currentRoom = false;

  function setRoom(id) {
    let oldRoom = currentRoom;

    var room = null
    for (const r of rooms) {
      if (r.id == id) {
        room = r
      }
    }
    currentRoom = room;

    console.log("setroom", rooms)

    $messages.empty();
    room.history.forEach(m => addChatMessage(m.msg));

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
      let sign = "# ";
      if (room.private) sign = "$ ";
      $('#channel-name').text(sign + room.name.replace(/</g, "&lt;").replace(/>/g, "&gt;"));
      $('#channel-description').text(`👤 ${room.members.length} | ${room.description.replace(/</g, "&lt;").replace(/>/g, "&gt;")}`);
      $roomList.find(`li[data-room=${room.id}]`).addClass("active").removeClass("unread");
    }

    $('.roomAction').css('visibility', (room.direct || room.forceMembership) ? "hidden" : "visible");
  }
  window.setRoom = setRoom;

  function setDirectRoomHeader(user) {
    $('#channel-name').text("@ " + user.replace(/</g, "&lt;").replace(/>/g, "&gt;"));
    $('#channel-description').text(`Direct message with ${user.replace(/</g, "&lt;").replace(/>/g, "&gt;")}`);
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

  async function sendMessage() {
    // retrieve input and sanitize against XSS attacks
    let input = $inputMessage.val().replace(/</g, "&lt;").replace(/>/g, "&gt;");

    // encrypt sanitized input:
    let encryption = aesEncrypt(input, username);
    let encrypted_message = encryption.encrypted_message;
    let encrypted_username = encryption.encrypted_username;
    let aes_Key = encryption.key;

    // encrypt key for each recipient
    var keyArray = [];

    for (const user of users) {
      var to_encrypt = new TextEncoder().encode(aes_Key);
          await importCryptoKey(JSON.parse(user.publicKey)).then(async (userPublicKey) => {
            await rsaEncrypt(to_encrypt, userPublicKey).then((encryptedKey) => {
              keyArray.push({username: user.username, encryptedKey: encryptedKey});
            })
          }) 
    }

    if (encryption && connected && currentRoom !== false) {
      $inputMessage.val('');
      const msg = {username: encrypted_username, message: encrypted_message, room: currentRoom.id};
      
      //addChatMessage(msg);
      socket.emit('new message', {msg: msg, keyArray: keyArray});
    }
  }
  

  function processEncryptedMsg(msg, aes_Key) {
    let authentication = "";
    let hmac_Key = CryptoJS.SHA256(aes_Key);

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

  function decryptProcessedMsg(msg, processed_msg, key) {
    // decrypt message and username
    msg.message = aesDecrypt(processed_msg.message_ciphertext, key, processed_msg.message_iv);
    msg.username = aesDecrypt(processed_msg.username_ciphertext, key, processed_msg.username_iv);
    msg.authentication = processed_msg.authentication;
    return msg;
  }

  function addChatMessage(msg) {
    if (msg.authentication == null) return

    // display time and message
    let time = new Date(msg.time).toLocaleTimeString('en-US', { hour12: false, 
                                                        hour  : "numeric", 
                                                        minute: "numeric"});

    $messages.append(`
      <div class="message">
        <div class="message-avatar"></div>
        <div class="message-textual">
          <span class="message-user">${msg.username.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</span>
          <span class="message-authentication" title="Authentication Status">${msg.authentication.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</span>
          <span class="message-time">${"(" + time + ")"}</span>
          <span class="message-content">${msg.message.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</span>
        </div>
      </div>
    `);

    $messages[0].scrollTop = $messages[0].scrollHeight;
  }

  function messageNotify(msg) {
    if (msg.direct)
      $userList.find(`li[data-direct="${msg.username.replace(/</g, "&lt;").replace(/>/g, "&gt;")}"]`).addClass('unread');
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


  socket.on('update_room', data => {
    if (data.room.history.length == 0) {
      updateRoom(data.room);
      updateRoomList();

      if (data.moveto)
        setRoom(data.room.id);

    } else {
      // room has message history, which is encrypted

      // retrieve public key messages
      callOnStore(async function (store) {
        var getKeys = store.get(username);
        getKeys.onsuccess = async function() {
          let rsaKeys = getKeys.result.keys;

          // initialize empty rooms and users
          var clone = structuredClone(data);
          clone.room.history = [];

          updateRoom(clone.room);
          updateRoomList();

          // retrieve every message
          for (const message of data.room.history) {
            for (const keyEntry of message.keyArray) {
              // fill room with messages if they can be decrypted
              if (keyEntry.username == username) {
                let encryptedAESkey = keyEntry.encryptedKey

                // decrypt every message
                await rsaDecrypt(encryptedAESkey, rsaKeys).then( async (decryption) => {
                  let decryptedAESkey = new TextDecoder("utf-8").decode(decryption)
                  message.msg = decryptProcessedMsg(message.msg, processEncryptedMsg(message.msg, decryptedAESkey), decryptedAESkey)

                  // add message to room
                  clone.room.history.push(message)

                }).then(() => {
                  updateRoom(clone.room)
                  updateRoomList();

                  if (data.moveto)
                    setRoom(data.room.id);
                })
              }
            }
          }
        }
      })
    }
      
  });

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
    updateUsers(data.users)
    updateRooms(data.rooms)
    updateRoomList();

    if (data.rooms.length > 0) {
      setRoom(data.rooms[0].id);
    }

    // retrieve public key messages
    callOnStore(async function (store) {
      var getKeys = store.get(username);
      getKeys.onsuccess = async function() {
        let rsaKeys = getKeys.result.keys;

        // initialize empty rooms and users
        var clone = structuredClone(data);
        for (const r of clone.rooms) {
          r.history = [];
        }
        updateRooms(clone.rooms)
        updateUsers(data.users)
        if (data.rooms.length > 0) {
          setRoom(data.rooms[0].id);
        }

        // retrieve every message
        for (const room of data.rooms) {
          for (const message of room.history) {
            for (const keyEntry of message.keyArray) {

              // fill room with messages if they can be decrypted
              if (keyEntry.username == username) {
                let encryptedAESkey = keyEntry.encryptedKey

                // decrypt every message
                await rsaDecrypt(encryptedAESkey, rsaKeys).then( async (decryption) => {
                  let decryptedAESkey = new TextDecoder("utf-8").decode(decryption)
                  message.msg = decryptProcessedMsg(message.msg, processEncryptedMsg(message.msg, decryptedAESkey), decryptedAESkey)

                  // update rooms and users
                  var index = data.rooms.indexOf(room)
                  clone.rooms[index].history.push(message)

                  updateRooms(clone.rooms);

                }).then(() => {
                  updateUsers(data.users)
                  updateRoomList();
                  if (data.rooms.length > 0) {
                    setRoom(data.rooms[0].id);
                  }
                })
              }
            }
          }
        }
      }
    })
  });

  socket.on('update_public_channels', (data) => {
    updateChannels(data.publicChannels);
  });

  // Whenever the server emits 'new message', update the chat body
  socket.on('new message', (data) => {

    // retrieve public key messages
    callOnStore(async function (store) {
      var getKeys = store.get(username);
      getKeys.onsuccess = async function() {
        let rsaKeys = getKeys.result.keys;

        // retrieve every message
        for (const keyEntry of data.keys) {
          if (keyEntry.username == username) {
            let encryptedAESkey = keyEntry.encryptedKey

            // decrypt message
            await rsaDecrypt(encryptedAESkey, rsaKeys).then( async (decryption) => {
              let decryptedAESkey = new TextDecoder("utf-8").decode(decryption)
              msg = decryptProcessedMsg(data, processEncryptedMsg(data, decryptedAESkey), decryptedAESkey);

              // find room in rooms
              const roomId = msg.room;
              for (const r of rooms) {
                if (r.id == roomId) {
                  room = r;
                }
              }

              // add message
              if (room) {
                room.history.push({msg: msg, keyArray: data.keys});
              }
              if (roomId == currentRoom.id) {
                addChatMessage(msg)
              } else { 
                messageNotify(msg)
              }
            })
          }
        }
      }
    })

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
    updateUser(data.user);
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
    callOnStore(function (store) {
      let getLocalDBkeys = store.get(username);
      getLocalDBkeys.onsuccess = async function() {
        publicKey = JSON.stringify(await exportCryptoKey(getLocalDBkeys.result.keys.publicKey));
        let data = {username: username, publicKey: publicKey};
        // perform request to server
        await socket.emit('join', data);
      }
      getLocalDBkeys.onerror = () => {
        alert("Could not retrieve registration data (i.e. local keys).")
      }
    })
  });

  socket.on('disconnect', () => {
  });

  socket.on('reconnect', () => {
    // join
    let data = {username: username, publicKey: publicKey}
    socket.emit('join', data)
  });

  socket.on('reconnect_error', () => {
  });

});

