# Copyright 2024 MELIK LEMARIEY
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
import argparse
import hashlib
import hmac
import json
import os
import requests
import logging
from datetime import datetime
import tenseal as ts
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
import subprocess
import base64
from session import initiate_session, get_session_data, update_session_data, display_session_data
import shutil
from validate import validate_url, validate_filename, validate_user_id, validate_token, validate_filepath, validate_hex_string

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class TransactionError(Exception):
    """Custom exception class for transaction errors."""
    pass

def generate_parameters(url_gen, data, output_file):
    """
    Generate DH parameters from a given URL and save them to an output file.
    
    Args:
        url_gen (str): The URL to generate parameters.
        data (dict): Data to be sent in the POST request.
        output_file (str): The file path where the parameters will be saved.
    
    Raises:
        requests.exceptions.RequestException: If there is an error with the request.
    """
    try:
        url_gen = validate_url(url_gen)
        output_file = validate_filename(output_file)
        
        response = requests.post(url_gen, data=data)
        response.raise_for_status()
        
        with open(output_file, 'wb') as file:
            file.write(response.content)
        print("Parameters generated and saved to parameters.pem")
    except (requests.exceptions.RequestException, ValueError) as e:
        print(f"Error generating parameters: {e}")

def wait_for_peer_verification(server_url, access_token, session_id, peer_user, max_attempts=10, wait_interval=5):
    """
    Wait for the peer user to pass verification.

    Args:
        server_url (str): The URL of the server.
        access_token (str): The access token for authorization.
        session_id (str): The ID of the session.
        peer_user (str): The username of the peer user.
        max_attempts (int, optional): Maximum number of attempts to check verification status. Defaults to 10.
        wait_interval (int, optional): Interval time (in seconds) between attempts. Defaults to 5.
    
    Returns:
        bool: True if the peer user passed verification, False otherwise.
    """
    try:
        server_url = validate_url(server_url)
        access_token = validate_token(access_token)
        session_id = validate_user_id(session_id)
        peer_user = validate_user_id(peer_user)
        
        for attempt in range(max_attempts):
            session_data = get_session_data(server_url, access_token, session_id)
            if session_data and session_data.get('status', {}).get(peer_user) == 'PASSED':
                logging.info(f"Peer {peer_user} has passed verification.")
                return True
            logging.info(f"Waiting for {peer_user} to pass verification. Attempt {attempt + 1}/{max_attempts}")
            time.sleep(wait_interval)
        logging.error(f"Verification by {peer_user} failed or timed out.")
        return False
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        return False

def load_parameters_from_server(url_load, data):
    """
    Load DH parameters from a given URL.

    Args:
        url_load (str): The URL to load parameters.
        data (dict): Data to be sent in the POST request.

    Returns:
        serialization.load_pem_parameters: Loaded DH parameters.

    Raises:
        requests.exceptions.RequestException: If there is an error with the request.
    """
    try:
        url_load = validate_url(url_load)
        
        response = requests.post(url_load, data=data)
        response.raise_for_status()
        
        json_response = response.json()
        print("Parameters successfully loaded.")
        parameters_pem = json_response['parameters'].encode()
        return serialization.load_pem_parameters(parameters_pem, backend=default_backend())
    except (requests.exceptions.RequestException, ValueError) as e:
        print(f"Error loading parameters: {e}")
        return None

def generate_keys(parameters, user_Sender):
    """
    Generate a pair of DH keys (private and public) and save them to disk.

    Args:
        parameters (dh.DHParameters): DH parameters for key generation.
        user_Sender (str): Identifier for the user client.
    
    Returns:
        private_key (dh.DHPrivateKey): The generated private key.
        pem_public_key (bytes): The generated public key in PEM format.
    """
    try:
        user_Sender = validate_user_id(user_Sender)
        
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_key_filename = f"{user_Sender}-private_key.pem"
        public_key_filename = f"{user_Sender}-public_key.pem"
        directory_path = f"./secure/PublicKey/{user_Sender}"
        os.makedirs(directory_path, exist_ok=True)
        with open(os.path.join(directory_path, private_key_filename), 'wb') as f:
            f.write(pem_private_key)
        with open(os.path.join(directory_path, public_key_filename), 'wb') as f:
            f.write(pem_public_key)

        return private_key, pem_public_key
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        return None, None

def upload_public_key(server_url, user_id, public_key_pem):
    """
    Upload a public key to the server.

    Args:
        server_url (str): The URL of the server.
        user_id (str): The user identifier.
        public_key_pem (bytes): The public key in PEM format.

    Returns:
        dict: The server response as a JSON object.

    Raises:
        Exception: If the upload fails.
    """
    try:
        server_url = validate_url(server_url)
        user_id = validate_user_id(user_id)
        
        url = f"{server_url}/upload_public_key"
        data = {'user_id': user_id, 'public_key': public_key_pem.decode('utf-8')}
        response = requests.post(url, json=data)
        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"Failed to upload public key: {response.status_code} - {response.text}")
            return response.json()
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        return {}

def get_public_key(base_url, username, access_token):
    """
    Retrieve a public key from the server.

    Args:
        base_url (str): The base URL of the server.
        username (str): The username to get the public key for.
        access_token (str): The access token for authorization.

    Returns:
        dict: The public key data as a JSON object.

    Raises:
        Exception: If the retrieval fails.
    """
    try:
        base_url = validate_url(base_url)
        username = validate_user_id(username)
        access_token = validate_token(access_token)
        
        public_key_url = f"{base_url}/public_key/{username}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        }
        response = requests.get(public_key_url, headers=headers)
        logging.info(f"Raw response from get_public_key: {response.text}")

        if response.status_code == 200:
            return response.json()
        else:
            logging.error(f"Failed to get public key for {username}. Status code: {response.status_code}")
            raise Exception(f"Failed to get public key for {username}")
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        raise Exception(f"Validation error: {e}")

def sha256(data):
    """
    Generate a SHA-256 hash for the given data.

    Args:
        data (str): The input data to hash.

    Returns:
        str: The resulting SHA-256 hash.
    """
    return hashlib.sha256(data.encode()).hexdigest()

def hash_wallet(base_directory, user):
    """
    Hash the contents of the wallet directory for a given user.

    Args:
        wallet_directory (str): The base directory of the wallet.
        user (str): The username whose wallet needs to be hashed.

    Returns:
        str: The resulting hash of the wallet contents, or None if the wallet does not exist.
    """
    try:
        base_directory = validate_filepath(base_directory, is_directory=True)
        user = validate_user_id(user)
        
        wallet_path = os.path.join(base_directory, 'wallet', f"{user}-encrypted_balance.json")
        logging.info(f"PLP Hashing wallet file at path: {wallet_path}")

        if not os.path.exists(wallet_path):
            logging.error(f"Wallet file {wallet_path} does not exist.")
            return None

        hasher = hashlib.sha256()
        try:
            with open(wallet_path, 'rb') as f:
                hasher.update(f.read())
            hash_result = hasher.hexdigest()
            logging.info(f"Successfully hashed wallet file. Hash: {hash_result}")
            return hash_result
        except Exception as e:
            logging.error(f"Failed to hash wallet file {wallet_path}: {e}")
            return None
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        return None

def notify_server_of_initiate(server_url, message):
    """
    Notify the server that ZoKrates verification has passed.

    Args:
        server_url (str): The URL of the server.
        message (str): The message to send to the server.
    """
    try:
        server_url = validate_url(server_url)
        
        url = f"{server_url}/initiate_transaction"
        data = {'message': message}
        response = requests.post(url, json=data)
        if response.status_code == 200:
            logging.info("Initiate successfully")
        else:
            logging.error(f"Failed to initiate: {response.status_code}, {response.text}")
    except ValueError as e:
        logging.error(f"Validation error: {e}")

def generate_hash(nonce, length, output_length):
    """
    Generate a truncated hash value from a nonce.

    Args:
        nonce (str): The input nonce.
        length (int): The length to truncate the nonce.
        output_length (int): The length to truncate the resulting hash.

    Returns:
        int: The resulting truncated hash value.
    """
    if not isinstance(nonce, str) or not isinstance(length, int) or not isinstance(output_length, int):
        raise ValueError("Invalid input types for generate_hash")

    truncated_input = nonce[:length]
    input_bytes = truncated_input.encode('utf-8')
    hash_object = hashlib.sha256()
    hash_object.update(input_bytes)
    hash_bytes = hash_object.digest()
    hash_int = int.from_bytes(hash_bytes, 'big')
    hash_str = str(hash_int)
    truncated_hash_str = hash_str[:output_length]
    truncated_hash_int = int(truncated_hash_str)
    return truncated_hash_int

def convert_derived_key_hex(derived_key_hex):
    """
    Convert a hexadecimal derived key to two 128-bit integers.

    Args:
        derived_key_hex (str): The derived key in hexadecimal format.

    Returns:
        tuple: Two 128-bit integers derived from the key.
    """
    full_key_int = int(derived_key_hex[:64], 16)
    full_key_int = int(derived_key_hex, 16)
    full_key_bit_length = full_key_int.bit_length()
    key_part1 = full_key_int >> 128
    key_part2 = full_key_int & ((1 << 128) - 1)
    logging.info(f"Full key bit length: {full_key_bit_length}")
    logging.info(f"Key part1 bit length: {key_part1.bit_length()}")
    logging.info(f"Key part2 bit length: {key_part2.bit_length()}")
    return key_part1, key_part2

def verify_script_integrity_path(expected_hash, file_path):
    """
    Verify the integrity of the script using SHA-256.

    Args:
        expected_hash (str): The expected SHA-256 hash of the script.
        file_path (str): The path to the script file.

    Raises:
        ValueError: If the script's hash does not match the expected hash.
    """
    if not is_hex(expected_hash):
        raise ValueError("Invalid expected hash")

    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            hasher.update(data)
    calculated_hash = hasher.hexdigest()
    print(f"Calculated hash: {calculated_hash}")  # Afficher le hachage calculé pour le débogage
    if calculated_hash != expected_hash:
        raise ValueError("Script integrity cannot be verified! The script has been altered.")

def verify_script_integrity(expected_hash):
    """
    Verify the integrity of the script using SHA-256.

    Args:
        expected_hash (str): The expected SHA-256 hash of the script.

    Raises:
        ValueError: If the script's hash does not match the expected hash.
    """
    if not is_hex(expected_hash):
        raise ValueError("Invalid expected hash")

    hasher = hashlib.sha256()
    with open(__file__, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            hasher.update(data)
    calculated_hash = hasher.hexdigest()
    print(f"Calculated hash: {calculated_hash}")
    if calculated_hash != expected_hash:
        raise ValueError("Script integrity cannot be verified! The script has been altered.")

def verify_wallet_integrity(initial_hash, base_directory, user):
    """
    Verify the integrity of the wallet by comparing the initial hash with the current hash.

    Args:
        initial_hash (str): The initial hash of the wallet.
        wallet_directory (str): The base directory of the wallet.
        user (str): The username whose wallet integrity needs to be verified.

    Returns:
        bool: True if the wallet integrity is verified, False otherwise.
    """
    try:
        initial_hash = validate_hex_string(initial_hash)
        base_directory = validate_filepath(base_directory, is_directory=True)
        user = validate_user_id(user)

        current_hash = hash_wallet(base_directory, user)
        if current_hash != initial_hash:
            logging.error(f"Wallet integrity verification failed for {user}.")
            return False
        logging.info(f"Wallet integrity verification passed for {user}.")
        return True
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        return False

def is_hex(s):
    """
    Check if a string is a valid hexadecimal string.

    Args:
        s (str): The string to check.

    Returns:
        bool: True if the string is a valid hexadecimal string, False otherwise.
    """
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False

def is_base64(s):
    """
    Check if a string is a valid base64 string.

    Args:
        s (str): The string to check.

    Returns:
        bool: True if the string is a valid base64 string, False otherwise.
    """
    try:
        base64.b64decode(s)
        return True
    except base64.binascii.Error:
        return False

def load_and_decrypt_balance(wallet_directory, context_directory, user):
    """
    Load and decrypt the balance from a wallet file for a specific user.

    Args:
        wallet_directory (str): The base directory of the wallet.
        context_directory (str): The directory containing the context files.
        user (str): The username whose balance needs to be loaded and decrypted.

    Returns:
        int: The decrypted balance of the user.

    Raises:
        ValueError: If the context data or encrypted balance data is invalid.
    """
    try:
        validate_filepath(wallet_directory, is_directory=True)
        validate_filepath(context_directory, is_directory=True)

        balance_path = os.path.join(wallet_directory, f'{user}-encrypted_balance.json')
        context_path = os.path.join(context_directory, f'{user}-full_context.json')
        
        validate_filepath(balance_path, is_directory=False)
        validate_filepath(context_path, is_directory=False)

        logging.info(f"1Loading balance from {balance_path}")
        logging.info(f"2Loading context from {context_path}")

        with open(balance_path, "r") as f:
            encrypted_balance_data = json.load(f)['encrypted_balance']
            logging.info(f"Encrypted balance data: {encrypted_balance_data}")

        with open(context_path, "r") as f:
            context_data = json.load(f)['context']
            logging.info(f"Context data: {context_data}")

            if is_hex(context_data):
                context_bytes = bytes.fromhex(context_data)
            elif is_base64(context_data):
                context_bytes = base64.b64decode(context_data)
            else:
                logging.error(f"Context data is not a valid hex or base64 string: {context_data}")
                raise ValueError("Context data is not a valid hex or base64 string.")
        
        context = ts.context_from(context_bytes)

        if is_hex(encrypted_balance_data):
            encrypted_balance_bytes = bytes.fromhex(encrypted_balance_data)
        elif is_base64(encrypted_balance_data):
            encrypted_balance_bytes = base64.b64decode(encrypted_balance_data)
        else:
            logging.error(f"Encrypted balance data is not a valid hex or base64 string: {encrypted_balance_data}")
            raise ValueError("Encrypted balance data is not a valid hex or base64 string.")

        encrypted_balance = ts.ckks_vector_from(context, encrypted_balance_bytes)
        decrypted_balance = encrypted_balance.decrypt()
        return round(decrypted_balance[0])
    except ValueError as e:
        logging.error(e)
        raise

def save_updated_balance(wallet_directory, context_directory, user, new_balance, description):
    """
    Save the updated encrypted balance to its corresponding JSON configuration file for a specific user.

    Args:
        wallet_directory (str): The base directory of the wallet.
        context_directory (str): The directory containing the context files.
        user (str): The username whose balance needs to be updated.
        new_balance (int): The new balance to be saved.
        description (str): A description of the update operation.
    
    Raises:
        ValueError: If the context data is invalid.
    """
    try:
        wallet_directory = validate_filepath(wallet_directory, is_directory=True)
        context_directory = validate_filepath(context_directory, is_directory=True)
        user = validate_user_id(user)

        context_path = os.path.join(context_directory, f"{user}-full_context.json")
        balance_path = os.path.join(wallet_directory, f"{user}-encrypted_balance.json")

        with open(context_path, "r") as f:
            context_data = json.load(f)['context']

            if is_hex(context_data):
                context_bytes = bytes.fromhex(context_data)
            elif is_base64(context_data):
                context_bytes = base64.b64decode(context_data)
            else:
                logging.error(f"Context data is not a valid hex or base64 string: {context_data}")
                raise ValueError("Context data is not a valid hex ou base64 string.")
        
        context = ts.context_from(context_bytes)
        encrypted_balance = ts.ckks_vector(context, [new_balance])
        with open(balance_path, "w") as f:
            json.dump({'encrypted_balance': encrypted_balance.serialize().hex()}, f, indent=4)
        logging.info(f"Updated balance saved to {balance_path} for {description}.")
    except ValueError as e:
        logging.error(f"Validation error: {e}")

def compute_zokrates_style_hash(balance, derived_key):
    """
    Compute a hash in the style expected by ZoKrates.

    Args:
        balance (int): The balance to include in the hash.
        derived_key_part (int): A part of the derived key to include in the hash.

    Returns:
        int: The resulting hash value.
    """
    if not isinstance(balance, int) or not isinstance(derived_key, int):
        raise ValueError("Invalid input types for compute_zokrates_style_hash")

    max_int_size = (1 << 128) - 1

    if balance < 0 or balance > max_int_size:
        logging.error(f"Balance out of bounds: {balance}")
        raise ValueError(f"Balance out of bounds: {balance}")
    if derived_key < 0 or derived_key > max_int_size:
        logging.error(f"Derived key part out of bounds: {derived_key}")
        raise ValueError(f"Derived key part out of bounds: {derived_key}")

    inputs = [balance % max_int_size, derived_key, 0, 0]
    input_bytes = b''.join(x.to_bytes(16, 'big', signed=False) for x in inputs)
    hash_output = hashlib.sha256(input_bytes).digest()
    return int.from_bytes(hash_output[:16], 'big')

def send_to_cometbft(tx_data, cometbft_url):
    """
    Send transaction data to the CometBFT server.

    Args:
        tx_data (str): The transaction data in JSON format.
        cometbft_url (str): The URL of the CometBFT server.

    Returns:
        dict: The response from the CometBFT server as a JSON object, or None if the request fails.
    """
    try:
        cometbft_url = validate_url(cometbft_url)

        headers = {"Content-Type": "application/json"}
        payload = {
            "method": "broadcast_tx_commit",
            "params": [tx_data],
            "jsonrpc": "2.0",
            "id": 1
        }
        response = requests.post(cometbft_url, headers=headers, data=json.dumps(payload))
        if response.status_code == 200:
            logging.info("Transaction successfully sent to CometBFT.")
            return response.json()
        else:
            logging.error(f"Failed to send transaction to CometBFT: {response.status_code} - {response.text}")
            return None
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        return None

def fetch_session_data(base_url, access_token, session_id):
    """
    Fetch session data from the server.

    Args:
        base_url (str): The base URL of the server.
        access_token (str): The access token for authorization.
        session_id (str): The ID of the session.

    Returns:
        dict: The session data as a JSON object, or None if the request fails.
    """
    try:
        base_url = validate_url(base_url)
        access_token = validate_token(access_token)
        session_id = validate_user_id(session_id)

        session_url = f"{base_url}/sessions/{session_id}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        }
        response = requests.get(session_url, headers=headers)
        if response.status_code == 200:
            logging.info("Session data retrieved successfully.")
            return response.json()
        else:
            logging.error(f"Failed to retrieve session data. Status code: {response.status_code}")
            return None
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        return None

def submit_user_public_key(server_url, session_id, user, public_key_pem, access_token):
    """
    Submit the user's public key to the server.

    Args:
        server_url (str): The URL of the server.
        session_id (str): The ID of the session.
        user (str): The username of the client.
        public_key_pem (bytes): The public key in PEM format.
        access_token (str): The access token for authorization.

    Returns:
        None
    """
    try:
        server_url = validate_url(server_url)
        session_id = validate_user_id(session_id)
        user = validate_user_id(user)
        access_token = validate_token(access_token)

        url = f"{server_url}/sessions/{session_id}/data"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        }
        data = {
            "user": user,
            "user_public_key": public_key_pem.decode('utf-8'),
            "data": ""
        }
        response = requests.post(url, headers=headers, json=data)
        if response.status_code == 200:
            logging.info(f"Public key for {user} submitted successfully.")
        else:
            logging.error(f"Failed to submit public key for {user}. Status code: {response.status_code}")
    except ValueError as e:
        logging.error(f"Validation error: {e}")

def derive_shared_key(private_key, peer_public_key):
    """
    Derive a shared key using the private key and the peer's public key.

    Args:
        private_key (dh.DHPrivateKey): The private key.
        peer_public_key (dh.DHPublicKey): The peer's public key.

    Returns:
        bytes: The derived shared key.
    """
    shared_key = private_key.exchange(peer_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    )
    return hkdf.derive(shared_key)

def generate_secure_salt(length=16):
    return os.urandom(length).hex()

def hmac_sha256(key, message):
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

def evaluate_polynomial(coefficients, x):
    result = 0
    for i, coef in enumerate(coefficients):
        result += coef * (x ** i)
    return result

def generate_proof(balance, amount, secret_salts, proof_output_directory):
    old_balance_poly = [balance] + [int(salt, 16) for salt in secret_salts[:3]]
    old_balance_evaluation = evaluate_polynomial(old_balance_poly, 1)
    expected_old_hash = hmac_sha256(secret_salts[0], str(old_balance_evaluation))
    
    new_balance = balance + amount
    new_balance_poly = [new_balance] + [int(salt, 16) for salt in secret_salts[3:]]
    new_balance_evaluation = evaluate_polynomial(new_balance_poly, 1)
    expected_new_hash = hmac_sha256(secret_salts[3], str(new_balance_evaluation))
    
    proof = {
        "expected_old_hash": expected_old_hash,
        "expected_new_hash": expected_new_hash,
        "secret_salts": secret_salts,
        "amount": amount
    }

    if not os.path.exists(proof_output_directory):
       os.makedirs(proof_output_directory)
    
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    proof_file_name = f"proof_{timestamp}.json"
    proof_file_path = os.path.join(proof_output_directory, proof_file_name)
    
    with open(proof_file_path, 'w') as proof_file:
        json.dump(proof, proof_file)

    return proof, proof_file_path

def read_proof(proof_file_path):
    with open(proof_file_path, 'r') as proof_file:
        proof = json.load(proof_file)
    return proof

def verify_proof(balance, proof):
    expected_old_hash = proof["expected_old_hash"]
    expected_new_hash = proof["expected_new_hash"]
    secret_salts = proof["secret_salts"]
    amount = proof["amount"]
    
    old_balance_poly = [balance] + [int(salt, 16) for salt in secret_salts[:3]]
    old_balance_evaluation = evaluate_polynomial(old_balance_poly, 1)
    old_hash = hmac_sha256(secret_salts[0], str(old_balance_evaluation))
    if old_hash != expected_old_hash:
        return False, "Old hash does not match expected hash"
    
    new_balance = balance + amount
    new_balance_poly = [new_balance] + [int(salt, 16) for salt in secret_salts[3:]]
    new_balance_evaluation = evaluate_polynomial(new_balance_poly, 1)
    new_hash = hmac_sha256(secret_salts[3], str(new_balance_evaluation))
    if new_hash != expected_new_hash:
        return False, "New hash does not match expected hash"
    
    return True, "Proof is valid"

def validate_inputs(balance, amount):
    assert isinstance(balance, int) and balance >= 0, "Invalid balance"
    assert isinstance(amount, int) and amount >= 0, "Invalid amount"

def run_python_command_add(witness_args, proof_output_directory, server_url, wallet_directory, context_directory, transaction_amount, user, peer_user, session_id, access_token, base_directory):
    """
    Execute Python-based ZKP commands for addition and handle session updates.

    Args:
        input_path (str): The path to the ZoKrates input file.
        witness_args (list): List of witness arguments for ZoKrates.
        proof_output_directory (str): Directory to save proof outputs.
        server_url (str): The URL of the server.
        wallet_directory (str): Directory containing wallet files.
        context_directory (str): Directory containing context files.
        transaction_amount (int): Amount to be added.
        user (str): Username of the client.
        peer_user (str): Username of the peer user.
        session_id (str): ID of the session.
        access_token (str): Access token for authorization.
        cometbft_url (str): URL of the CometBFT server.

    Returns:
        bool: True if the command execution and updates are successful, False otherwise.
    """
    try:
        server_url = validate_url(server_url)
        wallet_directory = validate_filepath(wallet_directory, is_directory=True)
        context_directory = validate_filepath(context_directory, is_directory=True)
        user = validate_user_id(user)
        peer_user = validate_user_id(peer_user)
        session_id = validate_user_id(session_id)
        access_token = validate_token(access_token)
        base_directory = validate_filepath(base_directory, is_directory=True)
        proof_output_directory = validate_filepath(proof_output_directory, is_directory=True) 

        for attempt in range(10):
            session_data = get_session_data(server_url, access_token, session_id)
            if session_data and session_data.get("sender_zkp_status") == "Success":
                break
            logging.info(f"Attempt {attempt + 1}/10 - Waiting for {peer_user}'s ZKP success...")
            time.sleep(5)
        else:
            logging.error(f"Verification by {peer_user} failed or timed out.")
            return False

        initial_hash = hash_wallet(base_directory, user)
        if initial_hash is None:
            return False

        balance = load_and_decrypt_balance(wallet_directory, context_directory, user)
        secret_salts = [generate_secure_salt() for _ in range(6)]

        proof, proof_file_path = generate_proof(balance, transaction_amount, secret_salts, proof_output_directory)
        logging.info(f"Proof generated: {proof}, {proof_file_path}")

        result, message = verify_proof(balance, proof)
        if not result:
            logging.error(f"Python-based ZKP verification failed: {message}")
            return False

        logging.info("Python-based ZKP verification passed.")
        
        update_data = {
            "receiver_zkp_status": "Success"
        }
        update_session_data(server_url, access_token, session_id, update_data)

        for attempt in range(10):
            session_data = get_session_data(server_url, access_token, session_id)
            if session_data and session_data.get("sender_balance") is not None:
                break
            logging.info(f"Attempt {attempt + 1}/10 - Waiting for Sender to be updated...")
            time.sleep(5)
        else:
            logging.error("Waiting for Sender_balance update failed or timed out.")
            return False

        if not verify_wallet_integrity(initial_hash, base_directory, user):
            return False

        actual_balance = load_and_decrypt_balance(wallet_directory, context_directory, user)
        new_balance = actual_balance + transaction_amount
        save_updated_balance(wallet_directory, context_directory, user, new_balance, "Addition")
        logging.info("Balances successfully updated.")

        balance_hash = hash_wallet(base_directory, user)
        if balance_hash is None:
            return False

        print(f"Receiver Balance Hash: {balance_hash}")

        update_data = {
            "receiver_wallet_hash": balance_hash
        }
        update_session_data(server_url, access_token, session_id, update_data)

        session_data = get_session_data(server_url, access_token, session_id)
        tx_data = {
            "session_id": session_id,
            "user": user,
            "session_data": session_data
        }

        display_session_data(server_url, access_token, session_id)

        return True
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        return False

def run_python_command_sub(witness_args, proof_output_directory, server_url, wallet_directory, context_directory, transaction_amount, user, peer_user, session_id, access_token, base_directory):
    """
    Execute Python-based ZKP commands for subtraction and handle session updates.

    Args:
        input_path (str): The path to the ZoKrates input file (not used in Python implementation).
        witness_args (list): List of witness arguments for ZoKrates (not used in Python implementation).
        proof_output_directory (str): Directory to save proof outputs (not used in Python implementation).
        server_url (str): The URL of the server.
        wallet_directory (str): Directory containing wallet files.
        context_directory (str): Directory containing context files.
        transaction_amount (int): Amount to be subtracted.
        user (str): Username of the client.
        peer_user (str): Username of the peer user.
        session_id (str): ID of the session.
        access_token (str): Access token for authorization.
        cometbft_url (str): URL of the CometBFT server.

    Returns:
        bool: True if the command execution and updates are successful, False otherwise.
    """
    try:
        server_url = validate_url(server_url)
        wallet_directory = validate_filepath(wallet_directory, is_directory=True)
        context_directory = validate_filepath(context_directory, is_directory=True)
        user = validate_user_id(user)
        peer_user = validate_user_id(peer_user)
        session_id = validate_user_id(session_id)
        access_token = validate_token(access_token)
        base_directory = validate_filepath(base_directory, is_directory=True)
        proof_output_directory = validate_filepath(proof_output_directory, is_directory=True) 

        initial_hash = hash_wallet(base_directory, user)
        if initial_hash is None:
            return False

        balance = load_and_decrypt_balance(wallet_directory, context_directory, user)
        logging.info("balance.")

        secret_salts = [generate_secure_salt() for _ in range(6)]

        proof, proof_file_path = generate_proof(balance, transaction_amount, secret_salts, proof_output_directory)
        logging.info(f"Proof generated: {proof}, {proof_file_path}")

        result, message = verify_proof(balance, proof)
        if not result:
            logging.error(f"Python-based ZKP verification failed: {message}")
            return False

        logging.info("Python-based ZKP verification passed.")

        update_data = {
            "sender_zkp_status": "Success"
        }
        update_session_data(server_url, access_token, session_id, update_data)

        for attempt in range(10):
            session_data = get_session_data(server_url, access_token, session_id)
            if session_data and session_data.get("receiver_zkp_status") == "Success":
                break
            logging.info(f"Attempt {attempt + 1}/10 - Waiting for Receiver_zkp_status to be Success...")
            time.sleep(5)
        else:
            logging.error("Waiting for Receiver_zkp_status failed or timed out.")
            return False

        # if not verify_wallet_integrity(initial_hash, base_directory, user):
        #     return False

        actual_balance = load_and_decrypt_balance(wallet_directory, context_directory, user)
        new_balance = actual_balance - transaction_amount
        save_updated_balance(wallet_directory, context_directory, user, new_balance, "Subtraction")
        logging.info("Balances successfully updated.")

        balance_hash = hash_wallet(base_directory, user)
        if balance_hash is None:
            return False

        print(f"Sender Balance Hash: {balance_hash}")

        update_data = {
            "sender_wallet_hash": balance_hash
        }
        update_session_data(server_url, access_token, session_id, update_data)

        session_data = get_session_data(server_url, access_token, session_id)
        tx_data = {
            "session_id": session_id,
            "user": user,
            "session_data": session_data
        }

        return True
    except ValueError as e:
        logging.error(f"Validation error: {e}")
        return False
