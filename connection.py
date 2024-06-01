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
from validate import validate_url, validate_username, validate_password

def register_user(base_url, username, password):
    """
    Registers a new user with the provided username and password.

    Args:
        base_url (str): The base URL of the server.
        username (str): The username of the user to be registered.
        password (str): The password of the user to be registered.

    Returns:
        bool: True if registration is successful, False if the user already exists.

    Raises:
        Exception: If registration fails due to other reasons.
    """
    try:
        base_url = validate_url(base_url)
        username = validate_username(username)
        password = validate_password(password)
    except ValueError as ve:
        logging.error(f"Validation error: {ve}")
        raise ve

    register_url = f"{base_url}/register"
    register_data = {"username": username, "password": password}
    response = requests.post(register_url, headers={"Content-Type": "application/json"}, data=json.dumps(register_data))

    if response.status_code == 201:
        logging.info("Registered successfully.")
        return True
    elif response.status_code == 409:
        logging.info("User already exists.")
        return False
    else:
        logging.error(f"Failed to register. Status code: {response.status_code}, Response: {response.text}")
        raise Exception("Registration failed")

def authenticate(base_url, username, password):
    """
    Authenticates a user and retrieves an access token. If authentication fails and the user does not exist,
    it attempts to register the user and retry authentication.

    Args:
        base_url (str): The base URL of the server.
        username (str): The username of the user.
        password (str): The password of the user.

    Returns:
        str: The access token if authentication is successful.

    Raises:
        Exception: If authentication or registration fails.
    """
    try:
        base_url = validate_url(base_url)
        username = validate_username(username)
        password = validate_password(password)
    except ValueError as ve:
        logging.error(f"Validation error: {ve}")
        raise ve

    auth_url = f"{base_url}/login"
    auth_data = {"username": username, "password": password}
    response = requests.post(auth_url, headers={"Content-Type": "application/json"}, data=json.dumps(auth_data))

    if response.status_code == 200:
        access_token = response.json().get("access_token")
        if not access_token:
            logging.error("No access token found in the response.")
            raise Exception("Authentication failed: No access token")
        logging.info("Authenticated successfully.")
        return access_token
    else:
        logging.error(f"Failed to authenticate. Status code: {response.status_code}, Response: {response.text}")
        if response.status_code == 401:
            logging.info("Attempting to register user and retry authentication.")
            try:
                registered = register_user(base_url, username, password)
                if registered:
                    response = requests.post(auth_url, headers={"Content-Type": "application/json"}, data=json.dumps(auth_data))
                    if response.status_code == 200:
                        access_token = response.json().get("access_token")
                        if not access_token:
                            logging.error("No access token found in the response after registration.")
                            raise Exception("Authentication failed after registration: No access token")
                        logging.info("Authenticated successfully after registration.")
                        return access_token
                    else:
                        logging.error(f"Failed to authenticate after registration. Status code: {response.status_code}, Response: {response.text}")
                        raise Exception("Authentication failed after registration")
            except Exception as e:
                logging.error(f"Registration and authentication process failed: {e}")
                raise e
        else:
            raise Exception("Authentication failed")
