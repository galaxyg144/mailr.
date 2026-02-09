import hashlib
import sys

def py_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        text = sys.argv[1]
        print(f"Python Hash: {py_hash(text)}")
