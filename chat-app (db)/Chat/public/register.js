const form = document.querySelector('form')
const username = document.querySelector('#username')
const password = document.querySelector('#password')
const display = document.querySelector('.error')

let keys = null
let publicKey = null

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

// POST request
async function performRequest() {
    generateCSRFToken();
    // perform request
    const res = await fetch('/api/auth/register', {
    method: 'POST',
    // sanitize against XSS attacks by replacing HTML tags
    body: JSON.stringify({username: DOMPurify.sanitize(username.value), 
                            password: password.value,
                            publicKey: publicKey, 
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
}

// Submit
form.addEventListener('submit', async (e) => {
    // check input lengths
    if (username.value.length < 1 || username.value.length > 30 || password.value.length < 8 || password.value.length > 30) {
    alert("Invalid input. Username should be between 1 and 30 (alphanumeric) characters long. Password should be at least 8 (alphanumeric) characters long.")
    }
    else {
    e.preventDefault()
    display.textContent = ''

    // process submit
    try {
        // check local client DB for keys
        callOnStore(function (store) {
        let getLocalDBkeys = store.get(DOMPurify.sanitize(username.value));
        getLocalDBkeys.onsuccess = async function() {
            // if the local client DB does not have RSA keys
            if (getLocalDBkeys.result == null) {
            //create keys
            keys = await generateRSAkeys()
            publicKey = JSON.stringify(await exportCryptoKey(keys.publicKey))

            // if request succeeds, store keys
            callOnStore(function (store) {
                let putKeys = store.put({id: DOMPurify.sanitize(username.value), keys: keys});
            });

            // perform request to server
            await performRequest()
            }
            // if the local client DB has RSA keys
            else {
            // export public key from local client DB
            console.log(getLocalDBkeys.result)
            publicKey = JSON.stringify(await exportCryptoKey(getLocalDBkeys.result.keys.publicKey))

            // perform request to server
            await performRequest()
            }
        }
        })

    } catch (err) {
        console.log(err.message)
    }
    }
})