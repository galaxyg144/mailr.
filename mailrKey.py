import secrets
import string
import hashlib
import os

# -------------------------
# Configuration
# -------------------------
PRIVATE_KEY_LENGTH = 32  # Recommended length for ECC or hex-based keys
KEY_DIR = "keys"         # folder to store keys

# -------------------------
# Character set
# -------------------------
CHARS = string.ascii_letters + string.digits + string.punctuation

# -------------------------
# Functions
# -------------------------
def generate_private_key(length=PRIVATE_KEY_LENGTH):
    """Generate a random private key with letters, digits, and symbols."""
    return ''.join(secrets.choice(CHARS) for _ in range(length))

def derive_public_key(private_key):
    """Derive the public key from the private key using SHA256."""
    return hashlib.sha256(private_key.encode()).hexdigest()

def save_keys(private_key, public_key, username):
    """Save keys to files in the KEY_DIR folder."""
    os.makedirs(KEY_DIR, exist_ok=True)
    priv_path = os.path.join(KEY_DIR, f"{username}-mailr-priv.key")
    pub_path = os.path.join(KEY_DIR, f"{username}-mailr-pub.key")

    with open(priv_path, "w") as f:
        f.write(private_key)
    with open(pub_path, "w") as f:
        f.write(public_key)

    print(f"[+] Private key saved to: {priv_path}")
    print(f"[+] Public key saved to:  {pub_path}")

# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    username = input("Enter username for this key: ").strip()
    if not username:
        print("[-] Error: Username cannot be empty.")
    else:
        private_key = generate_private_key()
        public_key = derive_public_key(private_key)
        save_keys(private_key, public_key, username)

        print("\n--- Keys Generated ---")
        print("PRIVATE KEY (keep this secret!):")
        print(private_key)
        print("\nPUBLIC KEY (store on server):")
        print(public_key)
