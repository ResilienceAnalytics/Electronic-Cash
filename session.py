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

import requests
import json
import logging
from validate import validate_url, validate_user_id

def initiate_session(base_url, access_token, participants):
    """
    Initiates a new session with the given participants and initializes the session block with default values.
    
    Parameters:
    base_url (str): The base URL of the server.
    access_token (str): The access token for authorization.
    participants (list): A list of participants for the session.
    
    Returns:
    dict: The session data returned from the server.
    """
    try:
        base_url = validate_url(base_url)
        participants = [validate_user_id(p) for p in participants]

        initiate_url = f"{base_url}/sessions/initiate"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        }
        data = {
            "participants": participants,
            "dh_parameters": "",
            "server_public_key": "",
            "Sender_public_key": "",
            "Receiver_public_key": "",
            "Sender_zkp_status": "Pending",
            "Receiver_zkp_status": "Pending",
            "Sender_balance": 0,
            "Receiver_balance": 0,
            "authentification": "Pending",
            "Sufficient_amount": "Pending",
            'sender_wallet_hash': "",
            'receiver_wallet_hash': ""
        }
        response = requests.post(initiate_url, headers=headers, data=json.dumps(data))

        response.raise_for_status()

        session_data = response.json()
        logging.info("Session initiated successfully.")
        return session_data

    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
        raise
    except Exception as err:
        logging.error(f"An error occurred: {err}")
        raise

def get_session_data(base_url, access_token, session_id):
    try:
        base_url = validate_url(base_url)
        session_id = validate_user_id(session_id)

        session_url = f"{base_url}/sessions/{session_id}"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        }
        response = requests.get(session_url, headers=headers)
        response.raise_for_status()

        logging.info("Session data retrieved successfully.")
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
        raise
    except Exception as err:
        logging.error(f"An error occurred: {err}")
        raise

def send_data(base_url, access_token, user, data):
    try:
        base_url = validate_url(base_url)
        user = validate_user_id(user)

        data_url = f"{base_url}/send_data"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        }
        payload = {
            "user": user,
            "data": data
        }
        response = requests.post(data_url, headers=headers, data=json.dumps(payload))

        response.raise_for_status()

        logging.info("Data submitted successfully.")
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
        raise
    except Exception as err:
        logging.error(f"An error occurred: {err}")
        raise

def list_sessions(base_url, access_token):
    try:
        base_url = validate_url(base_url)

        sessions_url = f"{base_url}/sessions"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        }
        response = requests.get(sessions_url, headers=headers)
        response.raise_for_status()

        sessions = response.json()
        logging.info("Sessions listed successfully.")
        return sessions
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
        raise
    except Exception as err:
        logging.error(f"An error occurred: {err}")
        raise

def update_session_data(base_url, access_token, session_id, update_data):
    """
    Updates the session data for a given session ID with new data.
    
    Parameters:
    base_url (str): The base URL of the server.
    access_token (str): The access token for authorization.
    session_id (str): The ID of the session.
    update_data (dict): The data to be added to the session.
    
    Returns:
    dict: The updated session data.
    """
    try:
        base_url = validate_url(base_url)
        session_id = validate_user_id(session_id)

        update_url = f"{base_url}/sessions/{session_id}/update"
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        }
        payload = {
            "update_data": update_data
        }
        
        logging.debug(f"Sending update request to {update_url}")
        logging.debug(f"Headers: {headers}")
        logging.debug(f"Payload: {json.dumps(payload)}")

        response = requests.post(update_url, headers=headers, data=json.dumps(payload))

        logging.debug(f"Response Status Code: {response.status_code}")
        logging.debug(f"Response Content: {response.text}")

        response.raise_for_status()

        updated_session_data = response.json()
        logging.info("Session data updated successfully.")
        return updated_session_data

    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
        raise
    except Exception as err:
        logging.error(f"An error occurred: {err}")
        raise

def cancel_session(base_url, access_token, session_id):
    try:
        base_url = validate_url(base_url)
        session_id = validate_user_id(session_id)

        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        response = requests.post(f"{base_url}/sessions/{session_id}/cancel", headers=headers)
        response.raise_for_status()

        logging.info("Session cancelled successfully.")
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
        raise
    except Exception as err:
        logging.error(f"An error occurred: {err}")
        raise

def display_session_data(base_url, access_token, session_id):
    """
    Display the session data for the given session ID.
    """
    try:
        base_url = validate_url(base_url)
        session_id = validate_user_id(session_id)

        url = f"{base_url}/sessions/{session_id}"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        response = requests.get(url, headers=headers)
        response.raise_for_status()

        session_data = response.json()
        print(json.dumps(session_data, indent=4))
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
        print(f"Failed to retrieve session data. Status code: {http_err.response.status_code}, Response: {http_err.response.text}")
    except Exception as err:
        logging.error(f"An error occurred: {err}")
        print(f"An error occurred: {err}")

def unregister_user(base_url, username, access_token):
    try:
        base_url = validate_url(base_url)
        username = validate_user_id(username)

        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        response = requests.post(f"{base_url}/unregister", headers=headers, json={"username": username})
        response.raise_for_status()

        logging.info("User unregistered successfully.")
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
        raise
    except Exception as err:
        logging.error(f"An error occurred: {err}")
        raise
