// Get the modal
var modal = document.getElementById('login');

// When the user clicks anywhere outside of the modal, close it
window.onclick = function(event) {
    if (event.target == modal) {
        modal.style.display = "none";
    }
}


function myFunction() {
    console.log("wokringlogin");
    var x = document.getElementById("login");
    if (x.style.display === "none") {
        x.style.display = "block";
    } else {
        x.style.display = "none";
    }
    var x = document.getElementById("testin");
    if (x.innerHTML == 'Create Account'){
        x.innerHTML = 'Login';
    }
    else {
        x.innerHTML == 'Create Account'
    }
    
}



function verifyUsernameAndPassword(username, password){
    //username = encrypt(username);
    //password = encrypt(password);
    var exists = socket.emit('verifyUsernameAndPassword', {username:username, password:password});
    return exists
}

function verifyLogin(){
    var username = document.getElementById('username').value;
    var password = document.getElementById('password').value;
    var verified = verifyUsernameAndPassword(username, password);
    
}


































