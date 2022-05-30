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

// RSA Export publicKey
async function exportCryptoKey(publicKey) {
  const exported = await window.crypto.subtle.exportKey(
    "jwk",
    publicKey
  );
  return exported;
}

// RSA Import publicKey
function importCryptoKey(jwk_publicKey) {
  return window.crypto.subtle.importKey(
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

////////////////////
// Client Storage //
////////////////////

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