module.exports = {
    setup: (Users, Rooms) => {
        console.log("hihikoekoek", Users)

        Rooms.addRoom("general", {forceMembership: true, description: "default general channel", private: false, encrypted: false});
        Rooms.addRoom("private" ,{forceMembership: true, description: "default private channel", private: true, encrypted: true});
    }
}