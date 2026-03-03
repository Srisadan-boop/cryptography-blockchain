"""
Cryptography and Blockchain Fundamentals
Menu-driven console application

Requirements:
    pip install cryptography
"""

import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature


# ─────────────────────────────────────────
#  1. SHA-256 Hashing
# ─────────────────────────────────────────
def sha256_hash():
    message = input("\nEnter message to hash: ").strip()
    digest = hashlib.sha256(message.encode()).hexdigest()
    print(f"\n  SHA-256 Hash:\n  {digest}")


# ─────────────────────────────────────────
#  2. Digital Signature
# ─────────────────────────────────────────
_key_pair = {"private": None, "public": None}
_last_signature = {"message": None, "sig": None}


def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _key_pair["private"] = private_key
    _key_pair["public"] = private_key.public_key()

    pub_pem = _key_pair["public"].public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()

    print("\n  [OK] RSA key pair generated successfully!")
    print(f"\n  Public Key:\n{pub_pem}")


def sign_message():
    if _key_pair["private"] is None:
        print("\n  [!] No key pair found. Please generate keys first (option 2).")
        return

    message = input("\nEnter message to sign: ").strip()
    sig = _key_pair["private"].sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    _last_signature["message"] = message
    _last_signature["sig"] = sig
    print(f"\n  [OK] Message signed successfully!")
    print(f"  Signature (hex, first 64 chars): {sig.hex()[:64]}...  [{len(sig)} bytes]")


def verify_signature():
    if _key_pair["public"] is None:
        print("\n  [!] No key pair found. Please generate keys first (option 2).")
        return
    if _last_signature["sig"] is None:
        print("\n  [!] No signature found. Please sign a message first (option 3).")
        return

    last = _last_signature["message"]
    message = input(f"\nEnter message to verify (last signed message: '{last}'): ").strip()
    try:
        _key_pair["public"].verify(
            _last_signature["sig"],
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        print("\n  [VALID] Signature is VALID — message is authentic.")
    except InvalidSignature:
        print("\n  [INVALID] Signature is INVALID — message does not match or was tampered with.")


# ─────────────────────────────────────────
#  3. Vehicle Registration System
# ─────────────────────────────────────────
_vehicles: dict = {}   # { plate: {owner, model} }


def register_vehicle():
    plate = input("\nEnter Number Plate: ").strip().upper()
    if not plate:
        print("  [!] Number plate cannot be empty.")
        return
    if plate in _vehicles:
        print(f"  [!] Error: Number plate '{plate}' is already registered. No duplicates allowed.")
        return

    owner = input("Enter Owner Name:    ").strip()
    model = input("Enter Vehicle Model: ").strip()

    if not owner or not model:
        print("  [!] Owner name and vehicle model cannot be empty.")
        return

    _vehicles[plate] = {"owner": owner, "model": model}
    print(f"\n  [OK] Vehicle registered successfully!")
    print(f"       Plate: {plate}  |  Owner: {owner}  |  Model: {model}")


def retrieve_vehicle():
    plate = input("\nEnter Number Plate to search: ").strip().upper()
    if plate in _vehicles:
        v = _vehicles[plate]
        print(f"\n  Vehicle Found:")
        print(f"    Number Plate : {plate}")
        print(f"    Owner        : {v['owner']}")
        print(f"    Model        : {v['model']}")
    else:
        print(f"\n  [!] Error: No vehicle found with number plate '{plate}'.")


def list_vehicles():
    if not _vehicles:
        print("\n  No vehicles registered yet.")
        return
    print(f"\n  {'Plate':<15} {'Owner':<20} Model")
    print("  " + "-" * 55)
    for plate, info in _vehicles.items():
        print(f"  {plate:<15} {info['owner']:<20} {info['model']}")


# ─────────────────────────────────────────
#  Main Menu
# ─────────────────────────────────────────
MENU = """
+------------------------------------------------+
|    Cryptography & Blockchain Fundamentals      |
+------------------------------------------------+
|  SHA-256 Hashing                               |
|    1. Hash a message                           |
+------------------------------------------------+
|  Digital Signature (RSA)                       |
|    2. Generate public/private key pair         |
|    3. Sign a message                           |
|    4. Verify a signature                       |
+------------------------------------------------+
|  Vehicle Registration System                   |
|    5. Register a vehicle                       |
|    6. Retrieve vehicle by number plate         |
|    7. List all registered vehicles             |
+------------------------------------------------+
|    0. Exit                                     |
+------------------------------------------------+
"""

ACTIONS = {
    "1": sha256_hash,
    "2": generate_keys,
    "3": sign_message,
    "4": verify_signature,
    "5": register_vehicle,
    "6": retrieve_vehicle,
    "7": list_vehicles,
}


def main():
    print("\n  Welcome to the Cryptography & Blockchain Fundamentals App!")
    while True:
        print(MENU)
        choice = input("  Select an option [0-7]: ").strip()
        if choice == "0":
            print("\n  Goodbye!\n")
            break
        action = ACTIONS.get(choice)
        if action:
            action()
        else:
            print("  [!] Invalid option. Please enter a number from 0 to 7.")
        input("\n  Press Enter to continue...")


if __name__ == "__main__":
    main()  
