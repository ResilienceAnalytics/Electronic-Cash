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


import os
import tenseal as ts
import json
import hashlib
import sys
import base64
import logging
import time
import requests
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from functions import hash_wallet
from dotenv import load_dotenv
import ipfshttpclient
import shutil

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

load_dotenv()
HASH_FILE_PATH = os.getenv('HASH_FILE_PATH')
BASE_DIRECTORY = os.getenv('BASE_DIRECTORY')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')
SERVER_URL = os.getenv('SERVER_URL')

def create_contexts():
    logging.info("Creating encryption context with CKKS scheme.")
    context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
    context.global_scale = 2**40
    context.generate_galois_keys()
    context.generate_relin_keys()
    return context

def encrypt_balance(context, balance):
    logging.info("Encrypting balance.")
    encrypted_balance = ts.ckks_vector(context, [balance])
    return encrypted_balance

def generate_salt():
    logging.info("Generating salt.")
    return os.urandom(16)

def wallet_exists(node_id):
    base_directory = os.path.join(BASE_DIRECTORY, 'secure', node_id)
    context_path = os.path.join(base_directory, "context", f"{node_id}-full_context.json")
    balance_path = os.path.join(base_directory, "wallet", f"{node_id}-encrypted_balance.json")
    proof_directory = os.path.join(base_directory, 'Proof')
    salt_path = os.path.join(base_directory, f"{node_id}-salt.bin")

    exists = (os.path.exists(context_path) and
              os.path.exists(proof_directory) and
              os.path.exists(balance_path) and
              os.path.exists(salt_path))

    return exists

def create_and_save_wallet(node_id, password=None):
    base_directory = os.path.join(BASE_DIRECTORY, 'secure', node_id)
    proof_directory = os.path.join(base_directory, 'Proof')

    if wallet_exists(node_id):
        logging.info(f"Wallet for node {node_id} already exists. Using existing wallet.")
        return False

    try:
        os.makedirs(base_directory, exist_ok=True)
        os.makedirs(proof_directory, exist_ok=True)

        context = create_contexts()

        if password == ADMIN_PASSWORD:
            initial_balance = 100000
        else:
            initial_balance = 0

        encrypted_balance = encrypt_balance(context, initial_balance)
        salt = generate_salt()

        logging.info(f"Saving context, encrypted balance, and salt for node {node_id}")
        
        if not (save_context(context, base_directory, node_id) and 
                save_encrypted_balance(encrypted_balance, base_directory, node_id) and 
                save_salt(salt, base_directory, node_id)):
            logging.error("Failed to save wallet data properly.")
            return False

        zkpsender_path = os.path.join(BASE_DIRECTORY,"Proof", 'ZKPPrivateExchangeSender.zok')
        zkpreceiver_path = os.path.join(BASE_DIRECTORY,"Proof", 'ZKPPrivateExchangeReceiver.zok')

        if os.path.exists(zkpsender_path) and os.path.exists(zkpreceiver_path):
            shutil.copy(zkpsender_path, proof_directory)
            shutil.copy(zkpreceiver_path, proof_directory)
            logging.info(f"Copied ZKP files to {proof_directory}.")
        else:
            logging.error("ZKP files not found. Make sure the paths are correct.")
            return False

        wallet_path = os.path.join(base_directory, "wallet", f"{node_id}-encrypted_balance.json")
        for _ in range(5):
            if os.path.exists(wallet_path):
                break
            time.sleep(1)
        else:
            logging.error(f"Attendre que le fichier soit créé Wallet file {wallet_path} does not exist.")
            return False

        balance_hash = hash_wallet(base_directory, node_id)
        if balance_hash is None:
            logging.error("Failed to hash wallet.")
            return False

        save_balance_hash(balance_hash, base_directory, node_id)

        if not send_wallet_hash_to_server(node_id, balance_hash):
            logging.error("Failed to send wallet hash to server.")
            return False


        logging.info(f"New wallet for node {node_id} created successfully with balance hash {balance_hash}.")
        return True
    except Exception as e:
        logging.error(f"Failed to create wallet for node {node_id}: {e}")
        return False

def save_balance_hash(balance_hash, base_directory, node_id):
    hash_file_path = os.path.join(base_directory, f"{node_id}-balance_hash.txt")
    with open(hash_file_path, 'w') as hash_file:
        hash_file.write(balance_hash)
    logging.info(f"Balance hash saved to {hash_file_path}.")

def save_context(context, base_directory, node_id):
    try:
        context_dir = os.path.join(base_directory, "context")
        os.makedirs(context_dir, exist_ok=True)
        context_path = os.path.join(context_dir, f"{node_id}-full_context.json")
        serialized_context = context.serialize(save_secret_key=True)
        context_data = base64.b64encode(serialized_context).decode('utf-8')
        with open(context_path, 'w') as f:
            json.dump({'context': context_data}, f, indent=4)
        logging.info(f"Context saved at: {context_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to save context: {e}")
        return False

def save_encrypted_balance(encrypted_balance, base_directory, node_id):
    try:
        wallet_dir = os.path.join(base_directory, "wallet")
        os.makedirs(wallet_dir, exist_ok=True)
        balance_path = os.path.join(wallet_dir, f"{node_id}-encrypted_balance.json")
        balance_data = base64.b64encode(encrypted_balance.serialize()).decode('utf-8')
        with open(balance_path, 'w') as f:
            json.dump({'encrypted_balance': balance_data}, f, indent=4)
        logging.info(f"Encrypted balance saved at: {balance_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to save encrypted balance: {e}")
        return False

def save_salt(salt, base_directory, node_id):
    try:
        salt_path = os.path.join(base_directory, f"{node_id}-salt.bin")
        with open(salt_path, 'wb') as f:
            f.write(salt)
        logging.info(f"Salt saved at: {salt_path}")
        return True
    except Exception as e:
        logging.error(f"Failed to save salt: {e}")
        return False

def load_context(node_id):
    try:
        base_directory = os.path.join(BASE_DIRECTORY, 'secure', node_id, 'context')
        context_path = os.path.join(base_directory, f"{node_id}-full_context.json")
        with open(context_path, 'r') as f:
            data = json.load(f)
        context_bytes = base64.b64decode(data['context'])
        return ts.context_from(context_bytes)
    except FileNotFoundError:
        logging.error(f"Context file not found for node {node_id}.")
        raise
    except Exception as e:
        logging.error(f"Failed to load context: {e}")
        raise

def load_encrypted_balance(node_id):
    try:
        context = load_context(node_id)
        base_directory = os.path.join(BASE_DIRECTORY, 'secure', node_id, 'wallet')
        balance_path = os.path.join(base_directory, f"{node_id}-encrypted_balance.json")
        with open(balance_path, 'r') as f:
            data = json.load(f)
        encrypted_balance = ts.ckks_vector_from(context, base64.b64decode(data['encrypted_balance']))
        return encrypted_balance
    except FileNotFoundError:
        logging.error(f"Encrypted balance file not found for node {node_id}.")
        raise
    except KeyError:
        logging.error(f"No valid encrypted balance key found in the configuration file.")
        raise
    except Exception as e:
        logging.error(f"Unexpected error occurred while loading encrypted balance: {e}")
        raise

def decrypt_balance(context, encrypted_balance):
    try:
        decrypted_balance = encrypted_balance.decrypt()
        logging.info("Balance decrypted successfully.")
        return decrypted_balance[0]
    except Exception as e:
        logging.error(f"Error decrypting balance: {e}")
        raise

def generate_dh_keys():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key, pem

def save_public_key(node_id, public_key):
    base_directory = os.path.join(BASE_DIRECTORY, 'secure', node_id)
    public_key_path = os.path.join(base_directory, f"{node_id}-public_key.pem")
    with open(public_key_path, 'wb') as f:
        f.write(public_key)

def load_public_key(node_id):
    base_directory = os.path.join(BASE_DIRECTORY, 'secure', node_id)
    public_key_path = os.path.join(base_directory, f"{node_id}-public_key.pem")
    if not os.path.exists(public_key_path):
        logging.error(f"Public key file does not exist for node {node_id}")
        raise FileNotFoundError("Public key file not found")

    try:
        with open(public_key_path, 'rb') as f:
            public_key_data = f.read()
        public_key = serialization.load_pem_public_key(public_key_data)
        return public_key
    except Exception as e:
        logging.error(f"Loading public key failed for node {node_id}: {e}")
        raise

def retrieve_public_key(node_id):
    base_directory = os.path.join(BASE_DIRECTORY, 'secure', node_id)
    public_key_path = os.path.join(base_directory, f"{node_id}-public_key.pem")
    if os.path.exists(public_key_path):
        with open(public_key_path, 'rb') as key_file:
            public_key = key_file.read()
        return public_key.decode('utf-8')
    else:
        return None

def list_wallets(base_directory=os.path.join(BASE_DIRECTORY, 'secure')):
    try:
        node_ids = [name for name in os.listdir(base_directory) if os.path.isdir(os.path.join(base_directory, name))]
        logging.info(f"Listed {len(node_ids)} wallets.")
        return node_ids
    except Exception as e:
        logging.error(f"Error listing wallets: {e}")
        return []

def load_wallet_hashes():
    if not os.path.exists(HASH_FILE_PATH):
        return {}
    try:
        with open(HASH_FILE_PATH, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        logging.error(f"Failed to decode JSON from {HASH_FILE_PATH}. Returning empty dictionary.")
        return {}

def save_wallet_hashes(wallet_hashes):
    with open(HASH_FILE_PATH, 'w') as f:
        json.dump(wallet_hashes, f, indent=4)

def upload_to_ipfs(file_path):
    try:
        client = ipfshttpclient.connect('/dns/localhost/tcp/5001/http')
        res = client.add(file_path)
        return res['Hash']
    except ipfshttpclient.exceptions.ConnectionError as e:
        logging.error(f"IPFS connection error: {e}")
        return None

def register_wallet_hash(user_id, wallet_hash):
    wallet_hashes = load_wallet_hashes()
    wallet_hashes[user_id] = wallet_hash
    save_wallet_hashes(wallet_hashes)
    ipfs_hash = upload_to_ipfs(HASH_FILE_PATH)
    return ipfs_hash

def download_from_ipfs(ipfs_hash, output_path):
    client = ipfshttpclient.connect('/dns/localhost/tcp/5001/http')
    res = client.get(ipfs_hash)
    os.rename(ipfs_hash, output_path)

def send_wallet_hash_to_server(node_id, balance_hash):
    try:
        url = f"{SERVER_URL}/register_wallet_hash"
        data = {'user_id': node_id, 'wallet_hash': balance_hash}
        response = requests.post(url, json=data)
        if response.status_code == 200:
            logging.info(f"Successfully sent wallet hash for {node_id} to server.")
            return True
        else:
            logging.error(f"Failed to send wallet hash for {node_id} to server: {response.status_code}, {response.text}")
            return False
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending wallet hash to server: {e}")
        return False
