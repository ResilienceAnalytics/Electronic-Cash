import re
import os
import logging


def validate_username(username):
    """Validate the provided username."""
    if not username or len(username) < 3:
        raise ValueError("Username must be at least 3 characters long.")
    return username

def validate_user_id(user_id):
    """Validate the user ID."""
    if not isinstance(user_id, str) or not re.match(r'^[a-zA-Z0-9_\-]+$', user_id):
        raise ValueError(f"Invalid user ID: {user_id}")
    return user_id

def validate_transaction_amount(amount):
    """Validate the transaction amount."""
    if not isinstance(amount, int) or amount <= 0:
        raise ValueError("The transaction amount must be a positive integer.")
    return amount

def validate_password(password):
    """Validate the password."""
    if not isinstance(password, str) or len(password) < 2:
        raise ValueError("The password must be at least 2 characters long.")
    return password

def validate_url(url):
    """Validate the server URL."""
    regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' # domain...
        r'localhost|' # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' # ...or ipv6
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    if re.match(regex, url) is not None:
        return url
    else:
        raise ValueError(f"Invalid URL: {url}")

def validate_filename(filename):
    """Validate the provided filename."""
    if not isinstance(filename, str) or not re.match(r'^[\w,\s-]+\.[A-Za-z]{3,4}$', filename):
        raise ValueError(f"Invalid filename: {filename}")
    return filename

def validate_token(token):
    """Validate the provided access token."""
    if not isinstance(token, str) or len(token) < 20:  # Example length check
        raise ValueError("Invalid access token")
    return token

def validate_hex_string(s):
    """
    Validate that the provided string is a valid hexadecimal string.
    
    Args:
        s (str): The string to validate.
    
    Returns:
        str: The validated hexadecimal string.
    
    Raises:
        ValueError: If the string is not a valid hexadecimal string.
    """
    if re.fullmatch(r'[0-9a-fA-F]+', s) is None:
        raise ValueError("The provided string is not a valid hexadecimal string.")
    return s

def validate_filepath(filepath, is_directory=False):
    """Validate the file or directory path."""
    if not isinstance(filepath, str):
        raise ValueError(f"Invalid filepath: {filepath}")
    if not os.path.exists(filepath):
        raise ValueError(f"Filepath does not exist: {filepath}")
    if is_directory:
        if not os.path.isdir(filepath):
            raise ValueError(f"Path is not a directory: {filepath}")
    else:
        if not os.path.isfile(filepath):
            raise ValueError(f"Path is not a file: {filepath}")
    return filepath

def validate_paths(base_directory, user):
    try:
        validate_filepath(base_directory, is_directory=True)
        validate_filepath(os.path.join(base_directory, "context"), is_directory=True)
        validate_filepath(os.path.join(base_directory, "wallet"), is_directory=True)
        validate_filepath(os.path.join(base_directory, "Proof"), is_directory=True)
        logging.info("All directories and files are validated successfully.")
    except ValueError as ve:
        logging.error(ve)
        return False
    return True
