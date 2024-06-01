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
import re
import argparse
import requests
import json
import logging
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from dotenv import load_dotenv
from functions import (
    generate_keys,
    fetch_session_data,
    submit_user_public_key,
    derive_shared_key,
    load_and_decrypt_balance,
    convert_derived_key_hex,
    compute_zokrates_style_hash,
    run_python_command_sub
)
from connection import authenticate, register_user
from session import initiate_session, update_session_data, display_session_data, cancel_session, unregister_user
from validate import validate_user_id, validate_transaction_amount, validate_password, validate_url, validate_filepath, validate_paths


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def main():
    parser = argparse.ArgumentParser(description="Manage transactions and cryptographic operations for the 'master' context.")
    parser.add_argument("--transaction_amount", type=int, required=True, help="Transaction amount to add or subtract")
    parser.add_argument("--password", type=str, required=True, help="Password for authentication")
    parser.add_argument("--participants", type=str, nargs=2, required=True, help="Participants in the session")

    args = parser.parse_args()
    try:
        transaction_amount = validate_transaction_amount(args.transaction_amount)
        password = validate_password(args.password)
        username = validate_user_id(args.participants[0])
        user = validate_user_id(args.participants[0])
        peer_user = validate_user_id(args.participants[1])
    except ValueError as ve:
        logging.error(ve)
        return

    node_id = user
    cometbft_url = "http://localhost:5000/cometbft/submit_tx"

    load_dotenv()
    try:
        SERVER_URL = validate_url(os.getenv('SERVER_URL'))
        BASE_DIRECTORY = os.getenv('BASE_DIRECTORY')
    except ValueError as ve:
        logging.error(ve)
        return

    base_directory = os.path.join(BASE_DIRECTORY, 'secure', user)
    if not validate_paths(base_directory, user):
        return

    context_directory = os.path.join(base_directory, "context")
    wallet_directory = os.path.join(base_directory, "wallet")
    proof_output_directory = os.path.join(base_directory, "Proof")

    # Define the specific filenames
    wallet_file = os.path.join(wallet_directory, f'{user}-encrypted_balance.json')
    context_file = os.path.join(context_directory, f'{user}-full_context.json')

    session_id = None

    try:
        access_token = authenticate(SERVER_URL, username, password)
        logging.info("Authenticated successfully.")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 401:
            logging.error(f"Failed to authenticate. Status code: {e.response.status_code}, Response: {e.response.text}")
            logging.info("Attempting to register user and retry authentication.")
            try:
                register_user(SERVER_URL, user, password)
                logging.info("Registered successfully.")
                access_token = authenticate(SERVER_URL, username, password)
                logging.info("Authenticated successfully after registration.")
            except requests.exceptions.HTTPError as reg_err:
                logging.error(f"Registration failed: {reg_err.response.text}")
                return
            except Exception as auth_err:
                logging.error(f"Authentication failed: {auth_err}")
                return
        else:
            logging.error(f"Authentication failed: {e.response.text}")
            return
    except Exception as e:
        logging.error(f"Authentication failed: {e}")
        return

    try:
        session_data = initiate_session(SERVER_URL, access_token, args.participants)
        logging.info("Session initiated successfully.")
        logging.info("Session Data: %s", json.dumps(session_data, indent=4))
        session_id = session_data['sessionId']
        dh_parameters_pem = session_data['dh_parameters']
        server_public_key_pem = session_data['server_public_key']

        dh_parameters = serialization.load_pem_parameters(dh_parameters_pem.encode(), backend=default_backend())
        server_public_key = serialization.load_pem_public_key(server_public_key_pem.encode(), backend=default_backend())

        my_private_key, my_public_key_pem = generate_keys(dh_parameters, 'Sender')
        logging.info("Sender's Public Key:\n%s", my_public_key_pem.decode())

        local_hash_path = os.path.join(base_directory, f'{node_id}-balance_hash.txt')
        with open(local_hash_path, 'r') as f:
            local_hash = f.read().strip()

        update_data = {
            "sender_public_key": my_public_key_pem.decode(),
            "sender_wallet_hash": local_hash
        }
        updated_session_data = update_session_data(SERVER_URL, access_token, session_id, update_data)

        max_attempts = 10
        for attempt in range(max_attempts):
            session_data = fetch_session_data(SERVER_URL, access_token, session_id)
            if session_data and 'receiver_public_key' in session_data and session_data['receiver_public_key']:
                receiver_public_key_pem = session_data['receiver_public_key']
                break
            logging.info(f"Attempt {attempt + 1}/{max_attempts} - Waiting for {peer_user}'s public key...")
            time.sleep(5)
        else:
            logging.error("Peer public key is not available after several attempts.")
            update_session_data(SERVER_URL, access_token, session_id, {"Sufficient_amount": "Failure"})
            cancel_session(SERVER_URL, access_token, session_id)
            return

        receiver_public_key = serialization.load_pem_public_key(receiver_public_key_pem.encode(), backend=default_backend())
        shared_secret_with_receiver = derive_shared_key(my_private_key, receiver_public_key)

        logging.info(f"Shared secret with receiver:\n{shared_secret_with_receiver.hex()}")

        actual_balance = load_and_decrypt_balance(wallet_directory, context_directory, user)
        new_balance = actual_balance - args.transaction_amount

        if new_balance < 0:
            update_data = {
                "Sufficient_amount": "Failure"
            }
            updated_session_data = update_session_data(SERVER_URL, access_token, session_id, update_data)
            logging.info("Insufficient balance for the transaction.")
            cancel_session(SERVER_URL, access_token, session_id)
            return

        if 'sender_wallet_hash' in session_data:
            remote_hash = session_data['sender_wallet_hash']
            if local_hash == remote_hash:
                logging.info("Hashes match.")
            else:
                logging.error("Hashes do not match.")
                cancel_session(SERVER_URL, access_token, session_id)
                return
        else:
            logging.error("Hash missed in session data.")
            cancel_session(SERVER_URL, access_token, session_id)
            return

        session_data = fetch_session_data(SERVER_URL, access_token, session_id)
        if 'authentication' in session_data:
            if session_data['authentication'] == "Failure":
                logging.error("Authentication failed.")
                cancel_session(SERVER_URL, access_token, session_id)
                return
        if 'Sufficient_amount' in session_data:
            if session_data['Sufficient_amount'] == "Failure":
                logging.error("Insufficient balance for the transaction.")
                cancel_session(SERVER_URL, access_token, session_id)
                return

        logging.info("out auth")

        derived_key_part1, derived_key_part2 = convert_derived_key_hex(shared_secret_with_receiver.hex())
        logging.info(f"derived_key_part1: '{derived_key_part1}' , derived_key_part2: '{derived_key_part2}'")
        old_hash = compute_zokrates_style_hash(actual_balance, derived_key_part1)
        new_hash = compute_zokrates_style_hash(new_balance, derived_key_part2)
        logging.info("out ZokStyle")

        witness_args = [actual_balance, args.transaction_amount, derived_key_part1, derived_key_part2, old_hash, new_hash]
        if run_python_command_sub(witness_args, proof_output_directory, SERVER_URL, wallet_directory, context_directory, args.transaction_amount, user, peer_user, session_id, access_token, base_directory):
            logging.info("ZKP verification passed for subtraction and balance updated.")
        else:
            logging.error("ELSE ZKP verification failed.")
            update_session_data(SERVER_URL, access_token, session_id, {"authentication": "Failure"})
            cancel_session(SERVER_URL, access_token, session_id)

        display_session_data(SERVER_URL, access_token, session_id)
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
        if session_id:
            try:
                cancel_session(SERVER_URL, access_token, session_id)
            except requests.exceptions.HTTPError as cancel_err:
                logging.error(f"Failed to cancel session: {cancel_err.response.text}")
    except Exception as err:
        logging.error(f"An error occurred: {err}")
        if session_id:
            try:
                cancel_session(SERVER_URL, access_token, session_id)
            except requests.exceptions.HTTPError as cancel_err:
                logging.error(f"Failed to cancel session: {cancel_err.response.text}")
   
    finally:
        try:
            final_balance = load_and_decrypt_balance(wallet_directory, context_directory, user)
            logging.info(f"Final balance: {final_balance}")
            logging.info("Program finished successfully.")

        except Exception as e:
            logging.error(f"Failed to load final balance: {e}")
            logging.info("Program finished Unsuccessfully.")

            
if __name__ == "__main__":
    main()
