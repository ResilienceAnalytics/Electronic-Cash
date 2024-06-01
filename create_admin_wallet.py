import os
import argparse
import tenseal as ts
import json
import base64
import logging
import time
import shutil
from functions import hash_wallet, verify_script_integrity_path, is_hex
from dotenv import load_dotenv
from wallet_management import save_context, save_encrypted_balance, save_salt, generate_salt, encrypt_balance, create_contexts, wallet_exists,send_wallet_hash_to_server 

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

load_dotenv()
EXPECTED_HASH = os.getenv('EXPECTED_HASH_CREATE_ADMIN_WALLET')
BASE_DIRECTORY = os.getenv('BASE_DIRECTORY')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

if  not is_hex(EXPECTED_HASH):
    raise ValueError('Invalid expected hash')

file_path = os.path.join(BASE_DIRECTORY, 'create_admin_wallet.py')
verify_script_integrity_path(EXPECTED_HASH, file_path)

def create_admin_wallet(node_id, password):
    if password != ADMIN_PASSWORD:
        logging.error("Invalid admin password.")
        return False

    base_directory = os.path.join(BASE_DIRECTORY, 'secure', node_id)
    proof_directory = os.path.join(base_directory, 'Proof')

    if wallet_exists(node_id):
        logging.info(f"Wallet for node {node_id} already exists. Using existing wallet.")
        return False

    try:
        os.makedirs(base_directory, exist_ok=True)
        os.makedirs(proof_directory, exist_ok=True)

        context = create_contexts()
        initial_balance = 1000000000000
        encrypted_balance = encrypt_balance(context, initial_balance)
        salt = generate_salt()

        logging.info(f"Saving context, encrypted balance, and salt for node {node_id}")
        
        if not (save_context(context, base_directory, node_id) and 
                save_encrypted_balance(encrypted_balance, base_directory, node_id) and 
                save_salt(salt, base_directory, node_id)):
            logging.error("Failed to save wallet data properly.")
            return False

        wallet_path = os.path.join(base_directory, "wallet", f"{node_id}-encrypted_balance.json")
        for _ in range(5):
            if os.path.exists(wallet_path):
                break
            time.sleep(1)
        else:
            logging.error(f"Waiting for Wallet file tob be created: {wallet_path} does not exist.")
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Create an admin wallet.')
    parser.add_argument('--node_id', required=True, help='The node ID for the wallet.')
    parser.add_argument('--password', required=True, help='The admin password.')

    args = parser.parse_args()

    success = create_admin_wallet(args.node_id, args.password)
    if success:
        print("Admin wallet created successfully.")
    else:
        print("Failed to create admin wallet.")
