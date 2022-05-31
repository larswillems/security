const form = document.querySelector('form')
const username = document.querySelector('#username')
const password = document.querySelector('#password')
const display = document.querySelector('.error')

// CSRF setup
function rnd_32byte_string(){
return CryptoJS.enc.Utf8.parse(CryptoJS.lib.WordArray.random(32)).toString(CryptoJS.enc.Utf8)
}
function generateCSRFToken() {
let csrf = rnd_32byte_string()
let max_age = 15*60 // 5 minutes

// set cookie with csrf token
document.cookie = "csrf=" + csrf + "; max-age=" + max_age + "; path=/; SameSite=Strict; Secure";
// set value hidden form field to csrf
document.getElementById("CSRFToken").value = csrf
return csrf
}

// Submit login request
form.addEventListener('submit', async (e) => {

// check input lengths
if (username.value.length < 1 || username.value.length > 30 || password.value.length < 8 || password.value.length > 30) {
    alert("Invalid input. Username should be between 1 and 30 (alphanumeric) characters long. Password should be at least 8 (alphanumeric) characters long.")
}

// perform request
else {
    e.preventDefault()
    display.textContent = ''

    try {
    generateCSRFToken();
    const res = await fetch('/api/auth/login', {
        method: 'POST',
        // sanitize against XSS attacks by replacing HTML tags
        body: JSON.stringify({username: DOMPurify.sanitize(username.value), 
                            password: password.value, 
                            csrf: document.getElementById("CSRFToken").value
                            }),
        headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin'
        })

    const data = await res.json()
    if (res.status === 201){
        location.assign('/main')
    } else {
        return display.textContent = `${data.message}. ${data.error ? data.error : ''}`
    }

    
    } catch (err) {
        console.log(err.message)
    }
}
})