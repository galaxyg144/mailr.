# mailr.
<<<<<<< HEAD
Im a "special" kind of extra. so im making my own mail client out of standard norms.
=======

A lightweight, secure local messaging system featuring cryptographic authentication and role-based access control.

## Overview

`mailr.` is a FastAPI-based messaging server that uses ECC/RSA signatures for user authentication. It provides a simple yet robust way to send and receive messages within a local network or private environment.

### Key Features
- **Cryptographic Auth**: Users register with public keys and authenticate via a challenge-response mechanism.
- **Role System**: Supports regular users (`#`), admins (`$`), and system entities (`~`).
- **Web UI**: Includes a clean, responsive web interface for managing keys and sending/receiving messages.
- **SQLite Backend**: Lightweight and zero-configuration data storage.

## Getting Started

### Prerequisites
- Python 3.8+
- [Optional] Virtual environment

### Installation
1. Clone the repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the server:
   ```bash
   uvicorn server:app --reload
   ```
4. Open `index.html` in your browser to access the client.

### Generating Keys
Use the `mailrKey.py` script to generate your private and public keys:
```bash
python3 mailrKey.py
```
- **Keep your private key secret!**
- Use the public key when registering on the server.

## Project Structure
- `server.py`: FastAPI backend and API routes.
- `database.py`: SQLite database interface.
- `mailrKey.py`: Utility for generating cryptographic keys.
- `src/`: Client-side assets (JS, CSS, HTML).
- `index.html`: Main application entry point.

## License
MIT License. See `LICENSE` for details.
>>>>>>> 640c7da (Initialize project and prepare for GitHub)
