const upperRooms = [];
let roomIdCounter = 0;

const roomsDatabase = require("./roomsDatabase")
const usersInDatabase = require("./usersInDatabase")
const Messages = require("./messagesDatabase")

async function getNewMemberId(){
    var length = -1
    await usersInDatabase.find().then((rooms) => {
        length = rooms.length  
      })
    return length
}


async function addMemberToRoom(roomId, username){

    await getNewMemberId().then(async (id) => {
        if (roomId >= 0){
            await usersInDatabase.create({
                "id": id,
                "roomId":roomId,
                "username":username,
                "added":true,
              })
        }
        
    })

    
}

async function deleteMemberOfRoom(roomId, username){
    await usersInDatabase.find({ id:roomId, username:username }).deleteOne().exec();
}

async function saveMessageInDatabase(msg){

    const username = msg.msg.username
    const message = msg.msg.message
    const roomId = msg.msg.room
    const time = msg.msg.time
    const authentication = msg.msg.authentication

    const keyArray = msg.keyArray

    await Messages.create({
        "roomId": roomId,
        "username":username,
        "message":message,
        "time":time,
        "authentication":authentication,
        "keyArray":keyArray
      })
}

async function retrieveMessagesOfRoom(roomId){
    var returnMessages = []
    await Messages.find({"roomId":roomId}).then((messages) => {
        returnMessages = messages
      })
    return returnMessages
}

async function retrieveMembersOfRoom(roomId){
    var returnMembers = []
    var rooms = await usersInDatabase.find({"roomId":roomId}).then((members) => {
        returnMembers = members
        console.log("----------------------------------------------------------------------------")
        console.log(members)
      })
    return returnMembers
}

class Room {
    constructor(id, name, options) {
        this.id   =  id;
        this.name =  name;

        this.description = options.description || "";
      
        this.forceMembership = !!options.forceMembership;
        this.private         = !!options.private;
        this.direct          = !!options.direct;
        this.encrypted       = !!options.encrypted;
  
        this.members = [];
        this.history = [];
    }

    getId() {
        return this.id;
    }

    async getMembers() {
        var returnMembers = []

        await retrieveMembersOfRoom(this.id).then((members) => {
            for (const m of members){
                returnMembers.push(m.username)
            }
        })

        return returnMembers
    }

    getMemberCount(){
        return this.members.length;
    }

    async addMember(user) {
        // check if user not already present
        if (this.members.indexOf(user.name) === -1){
            await addMemberToRoom(this.id, user.name).then((x) => {
                this.members.push(user.name);
            })
        }              
    }

    async removeMember(user) {
        const idx = this.members.indexOf(user.name);
        if (idx >= 0){
            await deleteMemberOfRoom(this.id, user.name).then((x) => {                
                this.members.splice(idx, 1);
            })
        }
    }

    async getHistory() {
        var returnMessages = []
        
        await retrieveMessagesOfRoom(this.id).then((messages) =>{
            console.log("----------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
            console.log(messages)
            
            for (const msg of messages){

                const username = msg.username
                const message = msg.message
                const roomId = msg.roomId
                const time = msg.time
                const authentication = msg.authentication

                const keyArray = msg.keyArray

                const newMessage = {
                    msg:{
                        username: username,
                        message: message,
                        room: roomId,
                        time: time,
                        authentication:authentication                        
                    },
                    keyArray: keyArray
                }
                console.log(newMessage)

                returnMessages.push(newMessage)
            }
        })

        return returnMessages
    }

    async addMessage(msg) {
        await saveMessageInDatabase(msg)
    }
}

async function getNewRoomId(){
    var length = -1
    await usersInDatabase.find().then((rooms) => {
        length = rooms.length  
      })
    return length
}


async function createRoom(name, options){
    var roomId = -1
    await getNewRoomId().then(async (roomIdCurr)=> {
        if (roomIdCurr >= 0){
            const description = options.description
            const private = options.private;
            const username = options.username;
            const encrypted = options.encrypted;
        
            await roomsDatabase.create({
                "id": roomIdCurr,
                "name":name,
                "description":description,
                "username":username,
                "private": private,
                "encrypted": encrypted
            })
            roomId = roomIdCurr
        }        
    })
    
    return roomId
}

async function checkIfRoomExists(name){
    var bool = true
    await roomsDatabase.find({"name":name}).then((rooms) => {
        if (rooms.length == 0){
            bool = false
        }
      })
    return bool
}

async function retrieveRoomsFromDatabase(username){
    var returnRooms = []

      await usersInDatabase.find({"username":username}).then(async (rooms) => {
        const mapLoop = async _ => {
          
            const promises = rooms.map(async room => {
              const numFruit = await roomsDatabase.find({"id":room.roomId}).then(async (rooms) => {
                  console.log(rooms.length, room.roomId)
                returnRooms.push(rooms)
                return rooms
              })

            })
            const idkk = await Promise.all(promises)
          }
        await mapLoop()

      })
      return returnRooms
}


var toType = function(obj) {
    return ({}).toString.call(obj).match(/\s([a-zA-Z]+)/)[1].toLowerCase()
  }



module.exports = {

    addRoom: async (name, options) => {
        var returnRoom = null
        await checkIfRoomExists(name).then(async (bool) => {
            if (bool){
                returnRoom = null
            }else {
                await createRoom(name, options).then((id) => {
                    var room = new Room(id, name, options);
                    upperRooms[id] = room;
                    returnRoom = room;
                }) 
            }
                
        })
        return returnRoom
    },

    getRooms: async (username) => {    
        var newRooms = [] 

        await retrieveRoomsFromDatabase(username).then(async (roomsFromDatabase) => {
            for (var roomm of roomsFromDatabase) {                
                var room=roomm[0]
                const newId = parseInt(room.id)
    
                const newName = room.name
                const newDescription = room.description
                const newPrivate = room.private
                const newEncrypted = room.encrypted
                const newForceMembership = room.forceMembership
                const newOptions = {
                description: newDescription,
                private: newPrivate,
                encrypted: newEncrypted,
                forceMembership: newForceMembership,
                direct: false
                }
    
                var newRoom = new Room(newId, newName, newOptions)

                await newRoom.getHistory().then((messages) => newRoom.history = messages)
                await newRoom.getMembers().then((members) => newRoom.members = members)

                upperRooms[newId] = newRoom;
                newRooms.push(newRoom)
               
            }
        })
        return newRooms;     
    },

    getForcedRooms: () => {
        return upperRooms.filter(r => r.forceMembership);
    },

    getRoom: id => {
        return upperRooms[id]
    }
}