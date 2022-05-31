module.exports = {
    setup: (Users, Rooms) => {

        Rooms.addRoom("general", {forceMembership: true, description: "default general channel", private: false, encrypted: false});
        Rooms.addRoom("private" ,{forceMembership: true, description: "interesting stuff 👀", private: true, encrypted: true});
    }
}