from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import secrets, hashlib, string, time
import database

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
database.init_db()

SYSTEM_ADDRESS = "mailr~mailr.qwert"

# -------------------
# Models
# -------------------
class User(BaseModel):
    address: str
    role: str
    public_key: str  # from mailrKey.py

class ChallengeRequest(BaseModel):
    address: str

class ChallengeResponse(BaseModel):
    address: str
    signature: str

class Message(BaseModel):
    sender: str
    recipient: str
    subject: str
    body: str
    global_msg: Optional[bool] = False
    timestamp: Optional[str] = None

# -------------------
# Helper functions
# -------------------
def create_challenge(address: str):
    challenge = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))
    database.upsert_challenge(address, challenge, time.time() + 30)
    return challenge

def verify_signature(address: str, signature_hex: str):
    # Retrieve challenge
    record = database.get_challenge(address)
    if not record or time.time() > record['expires']:
        return False
        
    # Retrieve user and public key
    user = database.get_user(address)
    if not user:
        return False
        
    try:
        import json
        import base64
        from cryptography.hazmat.primitives.asymmetric import ec, utils
        from cryptography.hazmat.primitives import hashes
        
        # Decode Base64 to JSON
        pub_key_json = base64.b64decode(user['public_key']).decode('utf-8')
        pub_key_obj = json.loads(pub_key_json)
        
        # Extract Signing JWK
        jwk = pub_key_obj['signing']
        
        # Helper for JWK Base64Url to int
        def b64url_to_int(s):
            padding_len = -len(s) % 4
            s += '=' * padding_len
            return int.from_bytes(base64.urlsafe_b64decode(s), byteorder='big')
            
        if pub_key_obj.get('algo') == 'ecc' or 'x' in jwk:
            # 2. ECC Path (ECDSA P-256)
            x = b64url_to_int(jwk['x'])
            y = b64url_to_int(jwk['y'])
            
            public_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
            
            # The signature comes as HEX string of raw bytes (R | S)
            sig_bytes = bytes.fromhex(signature_hex)
            
            # WebCrypto provides raw (R|S), cryptography needs DER
            r = int.from_bytes(sig_bytes[:32], byteorder='big')
            s = int.from_bytes(sig_bytes[32:], byteorder='big')
            der_sig = utils.encode_dss_signature(r, s)
            
            public_key.verify(
                der_sig,
                record['challenge'].encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        else:
            # Fallback to RSA if still present (for transition safety until wipe)
            from cryptography.hazmat.primitives.asymmetric import rsa, padding
            n = b64url_to_int(jwk['n'])
            e = b64url_to_int(jwk['e'])
            public_key = rsa.RSAPublicNumbers(e, n).public_key()
            signature_bytes = bytes.fromhex(signature_hex)
            public_key.verify(
                signature_bytes,
                record['challenge'].encode('utf-8'),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256()
            )
            return True
            
    except Exception as exc:
        print(f"Verification Error: {exc}")
        return False

def create_session(address: str):
    token = secrets.token_hex(16)
    database.upsert_session(address, token, time.time() + 3600)
    return token

def authenticate(token: str):
    session = database.get_session(token)
    if not session or time.time() > session['expires']:
        raise HTTPException(status_code=403, detail="Invalid or expired session")
    return session['address']

def role(address: str):
    if "$" in address: return "$"
    if "#" in address: return "#"
    if "~" in address: return "~"
    return "#"

def send_system_message(recipient: str, subject: str, body: str):
    msg = {
        "sender": SYSTEM_ADDRESS,
        "recipient": recipient,
        "subject": subject,
        "body": body,
        "timestamp": datetime.now().isoformat(),
        "global_msg": False
    }
    database.add_message(msg)

# Key generation helpers
def generate_private_key(length=50):
    """Generate a random private key."""
    import secrets
    import string
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(chars) for _ in range(length))

def derive_public_key(private_key: str):
    """Derive public key from private key using SHA256."""
    return hashlib.sha256(private_key.encode()).hexdigest()

# -------------------
# Routes
# -------------------
@app.post("/keygen")
def keygen():
    """Generate a new keypair."""
    private_key = generate_private_key()
    public_key = derive_public_key(private_key)
    return {
        "private_key": private_key,
        "public_key": public_key
    }

@app.post("/register")
def register(user: User):
    if user.address == SYSTEM_ADDRESS:
        raise HTTPException(status_code=400, detail="Cannot register system address")
    if database.get_user(user.address):
        raise HTTPException(status_code=400, detail="User exists")
    if user.role != "#":
        raise HTTPException(status_code=400, detail="Only regular role (#) can be registered via API")
    database.add_user(user.dict())
    return {"status": "registered", "address": user.address}

@app.post("/auth/challenge")
def auth_challenge(req: ChallengeRequest):
    user = database.get_user(req.address)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    challenge = create_challenge(req.address)
    return {"challenge": challenge}

@app.post("/auth/verify")
def auth_verify(resp: ChallengeResponse):
    if verify_signature(resp.address, resp.signature):
        token = create_session(resp.address)
        return {"status": "authenticated", "session_token": token}
    raise HTTPException(status_code=403, detail="Signature failed")

@app.post("/send")
def send_message(msg: Message, session_token: str):
    sender_address = authenticate(session_token)
    sender = database.get_user(sender_address)
    recipient = database.get_user(msg.recipient)
    if not recipient:
        raise HTTPException(status_code=400, detail="Recipient missing")
    
    s_role = sender["role"]
    r_role = recipient["role"]

    # Role Legend Enforcement
    if r_role == "~" and recipient["address"] != SYSTEM_ADDRESS:
         raise HTTPException(status_code=403, detail="Invalid system address")

    if s_role == "#":
        if r_role == "~":
            send_system_message(sender_address, "Delivery Error", "Regular users cannot send messages to system addresses.")
            raise HTTPException(status_code=403, detail="Regulars cannot send to system")
        # # -> $ and # -> # are allowed
    elif s_role == "~":
        if r_role == "~":
            send_system_message(sender_address, "Delivery Error", "System loopback (system to system) is not permitted.")
            raise HTTPException(status_code=403, detail="System cannot send to system")
        # ~ -> $ and ~ -> # are allowed
    elif s_role == "$":
        # $ -> # and $ -> $ are allowed
        # $ -> ~ triggers echoing
        if r_role == "~":
            msg.timestamp = datetime.now().isoformat()
            database.add_message(msg.dict())
            echoes = []
            for user in database.get_all_users():
                u_addr = user["address"]
                u_role = user["role"]
                # Echo to all # and $
                if u_role in ["#", "$"]:
                    echo = msg.dict().copy()
                    echo['recipient'] = u_addr
                    # Mark as system message source?
                    database.add_message(echo)
                    echoes.append(u_addr)
            return {"status": "sent to system, echoed to all users", "echoed_to": echoes}

    msg.timestamp = datetime.now().isoformat()
    database.add_message(msg.dict())

    return {"status": "sent", "to": msg.recipient}

@app.get("/inbox")
def get_inbox(session_token: str):
    address = authenticate(session_token)
    user = database.get_user(address)
    inbox = database.get_inbox_messages(address, user["role"])
    return {"inbox": inbox}
