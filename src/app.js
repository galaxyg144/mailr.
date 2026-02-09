let sessionToken = null;
let currentUser = null;
const API = "http://127.0.0.1:8000";
const DOMAIN = "mailr.qwert";

// Helper: Build full address from username and role
function buildAddress(username, role) {
    // Remove any spaces and validate
    username = username.replace(/\s+/g, '');
    if (!username) return '';
    return `${username}${role}${DOMAIN}`;
}

// Helper: Extract username from full address
function extractUsername(address) {
    // Extract everything before the role symbol
    const match = address.match(/^([^#$~]+)/);
    return match ? match[1] : '';
}

// View Management
function showView(viewName) {
    document.querySelectorAll('.view').forEach(v => v.style.display = 'none');
    document.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));

    if (viewName === 'inbox') {
        document.getElementById('inboxView').style.display = 'block';
        document.querySelectorAll('.sidebar-item')[0].classList.add('active');
        if (sessionToken) loadInbox();
    } else if (viewName === 'spam') {
        document.getElementById('spamView').style.display = 'block';
        document.querySelectorAll('.sidebar-item')[1].classList.add('active');
    } else if (viewName === 'trash') {
        document.getElementById('trashView').style.display = 'block';
        document.querySelectorAll('.sidebar-item')[2].classList.add('active');
    } else if (viewName === 'compose') {
        if (!sessionToken) {
            alert('Please login first');
            showLoginModal();
            return;
        }
        document.getElementById('composeView').style.display = 'block';
        document.querySelectorAll('.sidebar-item')[3].classList.add('active');
    }
}

// Modal Management
function showRegisterModal() {
    document.getElementById('registerModal').classList.add('active');
}

function closeRegisterModal() {
    document.getElementById('registerModal').classList.remove('active');
}

function showLoginModal() {
    document.getElementById('loginModal').classList.add('active');
}

function closeLoginModal() {
    document.getElementById('loginModal').classList.remove('active');
}

// File Upload Handler for Private Key
function handleKeyFileUpload(input) {
    const file = input.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function (e) {
        document.getElementById('loginPrivateKey').value = e.target.result.trim();
    };
    reader.readAsText(file);
}

// Registration
async function register(event) {
    event.preventDefault();
    const username = document.getElementById('regUsername').value.replace(/\s+/g, '').trim();
    const role = document.getElementById('regRole').value;
    const public_key = document.getElementById('regPublicKey').value.trim();

    if (!username) {
        alert('Username cannot be empty');
        return;
    }

    if (/\s/.test(document.getElementById('regUsername').value)) {
        alert('Username cannot contain spaces');
        return;
    }

    const address = buildAddress(username, role);

    try {
        const resp = await fetch(`${API}/register`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ address, role, public_key })
        });
        const data = await resp.json();

        if (resp.ok) {
            alert(`Registration successful! Your address is: ${address}\nYou can now login.`);
            closeRegisterModal();
            showLoginModal();
        } else {
            alert(`Registration failed: ${data.detail}`);
        }
    } catch (error) {
        alert('Registration failed: ' + error.message);
    }
}

// Login
async function login(event) {
    event.preventDefault();
    const username = document.getElementById('loginUsername').value.replace(/\s+/g, '').trim();
    const role = document.getElementById('loginRole').value;
    const privateKey = document.getElementById('loginPrivateKey').value.trim();
    const rememberMe = document.getElementById('rememberMe').checked;

    if (!username) {
        alert('Username cannot be empty');
        return;
    }

    const address = buildAddress(username, role);

    try {
        // Step 1: Get challenge
        const chResp = await fetch(`${API}/auth/challenge`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ address })
        });

        if (!chResp.ok) {
            const err = await chResp.json();
            alert(`Challenge failed: ${err.detail}`);
            return;
        }

        const chData = await chResp.json();
        const challenge = chData.challenge;

        // Step 2: Sign challenge with ECDSA
        let privateKeyObj;
        try {
            privateKeyObj = JSON.parse(atob(privateKey));
        } catch (e) {
            alert("Invalid Private Key format. Please use the new key generator.");
            return;
        }

        const signingJwk = privateKeyObj.signing;

        // Import Signing Key
        const key = await window.crypto.subtle.importKey(
            "jwk",
            signingJwk,
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            false,
            ["sign"]
        );

        // Sign Challenge
        const signatureBuffer = await window.crypto.subtle.sign(
            {
                name: "ECDSA",
                hash: { name: "SHA-256" },
            },
            key,
            new TextEncoder().encode(challenge)
        );

        // Convert signature to Hex string
        const signatureArray = Array.from(new Uint8Array(signatureBuffer));
        const sig = signatureArray.map(b => b.toString(16).padStart(2, '0')).join('');

        // Step 3: Verify
        const verifyResp = await fetch(`${API}/auth/verify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ address, signature: sig })
        });

        const verifyData = await verifyResp.json();
        if (verifyData.session_token) {
            sessionToken = verifyData.session_token;
            currentUser = address;
            document.getElementById('loginStatus').innerHTML = `logged in as <b>${address}</b> | <a onclick="logout()" style="cursor: pointer;">logout</a>`;

            // Handle Remember Me
            if (rememberMe) {
                localStorage.setItem('mailr_privkey', privateKey);
                localStorage.setItem('mailr_username', username);
                localStorage.setItem('mailr_role', role);
            }

            closeLoginModal();
            loadInbox();
        } else {
            alert(`Login failed: ${verifyData.detail || 'Unknown error'}`);
        }
    } catch (error) {
        alert('Login failed: ' + error.message);
    }
}

// Logout
function logout() {
    sessionToken = null;
    currentUser = null;
    document.getElementById('loginStatus').textContent = 'Not logged in';
    document.getElementById('inboxMessages').innerHTML = '<div class="empty-state">Please login to view messages</div>';
    document.getElementById('inboxMessages').innerHTML = '<div class="empty-state">Please login to view messages</div>';

    // Clear Remember Me if explicitly logging out? 
    // Usually logout clears session but keeping key for next login is convenient.
    // Let's keep it, but clear session.
    // Uncomment next line to force clear key on logout:
    // localStorage.removeItem('mailr_privkey');

    showLoginModal();
}

// Send Message
async function sendMessage(event) {
    event.preventDefault();
    if (!sessionToken) {
        alert('Please login first');
        return;
    }

    const recipientInput = document.getElementById('recipient').value;
    const subject = document.getElementById('subject').value;
    const body = document.getElementById('body').value;
    const global_msg = document.getElementById('global').checked;

    // Build recipient address if it's just a username
    let recipient = recipientInput;
    if (!recipientInput.includes('@') && !recipientInput.includes('~')) {
        // Assume it's a username, append #mailr.qwert
        recipient = buildAddress(recipientInput.replace(/\s+/g, ''), '#');
    }

    try {
        const resp = await fetch(`${API}/send?session_token=${sessionToken}`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                sender: currentUser,
                recipient,
                subject,
                body,
                global_msg
            })
        });

        const data = await resp.json();
        if (resp.ok) {
            alert('Message sent successfully!');
            document.getElementById('recipient').value = '';
            document.getElementById('subject').value = '';
            document.getElementById('body').value = '';
            document.getElementById('global').checked = false;
            showView('inbox');
        } else {
            alert(`Send failed: ${data.detail}`);
        }
    } catch (error) {
        alert('Send failed: ' + error.message);
    }
}

// Load Inbox
async function loadInbox() {
    if (!sessionToken) return;

    try {
        const resp = await fetch(`${API}/inbox?session_token=${sessionToken}`);
        const data = await resp.json();

        const inboxDiv = document.getElementById('inboxMessages');
        if (data.inbox.length === 0) {
            inboxDiv.innerHTML = '<div class="empty-state">No messages yet</div>';
            document.getElementById('unreadCount').textContent = '';
            return;
        }

        inboxDiv.innerHTML = '';
        data.inbox.forEach(m => {
            const msgDiv = document.createElement('div');
            msgDiv.className = 'message';
            msgDiv.innerHTML = `
                <div class="message-header">
                    <span class="message-sender">${m.sender}</span>
                    <span class="message-time">${new Date(m.timestamp).toLocaleString()}</span>
                </div>
                <div class="message-subject">${m.subject}</div>
                <div class="message-body">${m.body}</div>
            `;
            inboxDiv.appendChild(msgDiv);
        });

        document.getElementById('unreadCount').textContent = `[${data.inbox.length}]`;
    } catch (error) {
        console.error('Failed to load inbox:', error);
    }
}

// Keygen Modal Management
function showKeygenModal() {
    document.getElementById('keygenModal').classList.add('active');
    document.getElementById('keygenContent').style.display = 'block';
    document.getElementById('keygenResult').style.display = 'none';
}

function closeKeygenModal() {
    document.getElementById('keygenModal').classList.remove('active');
}

// Generate Keys
async function generateKeys() {
    try {
        const resp = await fetch(`${API}/keygen`, {
            method: "POST",
            headers: { "Content-Type": "application/json" }
        });
        const data = await resp.json();

        if (resp.ok) {
            document.getElementById('generatedPublicKey').value = data.public_key;
            document.getElementById('generatedPrivateKey').value = data.private_key;
            document.getElementById('keygenContent').style.display = 'none';
            document.getElementById('keygenResult').style.display = 'block';

            // Show security warning popup
            setTimeout(() => {
                alert('⚠️ KEEP YOUR PRIVATE KEY SAFE!\n\nNever share your private key with anyone.\nConsider storing it in a hidden folder like .mailrkeys');
            }, 300);
        } else {
            alert('Key generation failed');
        }
    } catch (error) {
        alert('Key generation failed: ' + error.message);
    }
}

// Download Public Key
function downloadPublicKey() {
    const publicKey = document.getElementById('generatedPublicKey').value;
    const blob = new Blob([publicKey], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'mailr-public.key';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Download Private Key
async function downloadPrivateKey() {
    const privateKey = document.getElementById('generatedPrivateKey').value;

    // Show another warning
    const confirmed = confirm('⚠️ WARNING!\n\nYou are about to download your PRIVATE KEY.\nThis key gives full access to your account.\n\nNEVER share this file with anyone!\n\nClick OK to proceed with download.');

    if (!confirmed) return;

    const blob = new Blob([privateKey], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'mailr-private.key';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    alert('💡 TIP: Store this file in a hidden folder like:\n~/.mailrkeys/\n\nKeep it safe and never commit it to version control!');
}

// Helper: SHA256
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Auto-refresh inbox every 5 seconds
setInterval(() => {
    if (sessionToken && document.getElementById('inboxView').style.display !== 'none') {
        loadInbox();
    }
}, 5000);

// Show login modal on load if not logged in
window.addEventListener('load', () => {
    // Check for stored key
    const storedKey = localStorage.getItem('mailr_privkey');
    const storedUser = localStorage.getItem('mailr_username');
    const storedRole = localStorage.getItem('mailr_role');

    if (storedKey && storedUser && storedRole) {
        // Pre-fill login modal
        document.getElementById('loginUsername').value = storedUser;
        document.getElementById('loginRole').value = storedRole;
        document.getElementById('loginPrivateKey').value = storedKey;
        document.getElementById('rememberMe').checked = true;
        updateLoginSuffix();
    }

    if (!sessionToken) {
        setTimeout(showLoginModal, 500);
    }
});
