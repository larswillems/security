





var MongoClient = require('mongodb').MongoClient;
var url = "mongodb://localhost:27017/";


function insertDatabase(name, password){
  MongoClient.connect(url, function(err, db) {
    if (err) throw err;
    var dbo = db.db("database");

    var myobj = { name: name, password: password};
    dbo.collection("users").insertOne(myobj, function(err, res) {
      if (err) throw err;
      console.log("1 document inserted");
      db.close();
    });
  });
}

function find(username){
  MongoClient.connect(url, function(err, db) {
    if (err) throw err;
    var dbo = db.db("database");
    dbo.collection("users").findOne({"username":"lars"}, function(err, result) {
      if (err) throw err;
      console.log(result.username);
      db.close();
    });
  });
}


//insertDatabase("ok", "oko");
find("ok")










