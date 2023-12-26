import requests
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from binascii import hexlify, unhexlify
import hashlib
import base58
import random

def generate_keypair(key_length_decimal, identical_digits, identical_digits_position, max_attempts=1000):
    key_length_hex = key_length_decimal * 2  # Konwertuj długość klucza na liczbę cyfr szesnastkowych

    for _ in range(max_attempts):
        random_digit = random.choice('0123456789ABCDEF')
        identical_digits_str = random_digit * identical_digits

        if identical_digits_position == 'start':
            private_key_hex = identical_digits_str + ''.join(random.choice('0123456789ABCDEF') for _ in range(key_length_hex - identical_digits))
        elif identical_digits_position == 'end':
            private_key_hex = ''.join(random.choice('0123456789ABCDEF') for _ in range(key_length_hex - identical_digits)) + identical_digits_str
        else:
            raise ValueError("Invalid position for identical digits. Use 'start' or 'end'.")

        break  # Jeżeli doszedłeś do tego miejsca, to znaczy, że klucz został wygenerowany zgodnie z oczekiwaniami

    else:
        raise ValueError("Unable to generate a key within the specified constraints after {} attempts.".format(max_attempts))

    private_key_bytes = unhexlify(private_key_hex)
    private_key = ec.derive_private_key(int.from_bytes(private_key_bytes, 'big'), ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()

    uncompressed_public_key = hexlify(public_key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)).decode()
    compressed_public_key = hexlify(public_key.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.CompressedPoint)).decode()

    uncompressed_address = generate_bitcoin_address(uncompressed_public_key)
    compressed_address = generate_bitcoin_address(compressed_public_key)

    return {
        "private_key": private_key_hex,
        "uncompressed_public_key": uncompressed_public_key,
        "compressed_public_key": compressed_public_key,
        "uncompressed_address": uncompressed_address,
        "compressed_address": compressed_address
    }

def generate_bitcoin_address(public_key_hex):
    public_key_bytes = unhexlify(public_key_hex)
    sha256_hash = hashlib.sha256(public_key_bytes).digest()
    ripemd160_hash = hashlib.new("ripemd160", sha256_hash).digest()
    extended_hash = b"\x00" + ripemd160_hash
    checksum = hashlib.sha256(hashlib.sha256(extended_hash).digest()).digest()[:4]
    binary_address = extended_hash + checksum
    bitcoin_address = base58.b58encode(binary_address).decode("utf-8")
    return bitcoin_address

def check_and_save_with_satoshi(address, private_key_hex):
    private_key_bytes = unhexlify(private_key_hex)
    private_key = ec.derive_private_key(int.from_bytes(private_key_bytes, 'big'), ec.SECP256K1(), default_backend())

    api_url = f"https://blockchain.info/q/getreceivedbyaddress/{address}"
    response = requests.get(api_url)

    try:
        satoshi_received = int(response.text)
    except ValueError:
        print(f"Error decoding Satoshi response for address {address}. Skipping...")
        return

    if satoshi_received > 0:
        save_to_file(address, private_key_hex, satoshi_received)
        print(f"Checking Uncompressed Address: {address}   Private Key: {private_key_hex}   Received {satoshi_received} satoshi. Saved to file.")

def save_to_file(address, private_key_hex, satoshi_received):
    with open("D:\\bitcoinpirate.txt", "a") as file:
        file.write(f"Address: {address}\nPrivate Key: {private_key_hex}\nSatoshi Received: {satoshi_received}\n\n")

if __name__ == "__main__":
    key_length_decimal = int(input("How many random HEX numbers in privkey: "))
    identical_digits = int(input("How many identical, random generated HEX numbers in privkey: "))
    identical_digits_position = input("Identical HEX numers on start or end of privkey ? (start/end): ")

    current_key = 0
    while current_key < 2**(4 * key_length_decimal):
        try:
            keypair = generate_keypair(key_length_decimal, identical_digits, identical_digits_position)
        except ValueError as e:
            print(e)
            break

        print("\nChecking Uncompressed Address:", keypair["uncompressed_address"])
        print("Private Key:", keypair["private_key"])  # Dodano wypisanie klucza prywatnego
        check_and_save_with_satoshi(keypair["uncompressed_address"], keypair["private_key"])

        print("\nChecking Compressed Address:", keypair["compressed_address"])
        print("Private Key:", keypair["private_key"])  # Dodano wypisanie klucza prywatnego
        check_and_save_with_satoshi(keypair["compressed_address"], keypair["private_key"])

        current_key += 1

        time.sleep(10)  # Ogranicz liczbę zapytań do jednego na 10 sekund
