Proof Of Concept with vulnerabilty

"It's often said, 'Not your keys, not your coins,' but in a literal and formal sense, you never truly have your tokens or coins. They are pieces of the blockchain that will never leave the chain. Here, however, with 'Your keys, your cash,' it's your cash that you have right in front of you."

At the moment, there is a critical vulnerability in the wallet generation. This is because the library produces a different hash for the same balance. I have already developed my own CKKS system (addition and subtraction in Go and Python, I need to conduct further tests).

Explanation of the Digital Cash Management System Using Blockchain

A digital cash management system that uses blockchain (not yet!) and the Internet for transactions. Here is how it works:

    Initialization and Balance Hash:
        Each user has a unique "hash" representing their cash balance. For example, User1 has an initial balance hash of 123.

    Transaction and Hash Update:
        When a user makes a transaction, their balance hash is updated. For example, after a transaction, User1's hash changes from 123 to 456.

    Storing Hashes:
        All balance hashes are recorded on a secure server.

    Authenticity Verification:
        When a user initiates a new transaction, the system compares the current balance hash (before the transaction) with the one stored in memory (the server).
        If the hashes do not match, it indicates possible tampering or fraudulent activity on the user's balance file.
        In this case, the transaction is denied to prevent fraud.

Additional Security Features

    Homomorphic Operations:
        The system uses homomorphic encryption, which allows transactions to be performed on encrypted data without needing to decrypt it first. This ensures that the data remains secure and private during processing.

    Zero-Knowledge Proofs (ZKP):
        Zero-knowledge proofs are generated to verify the authenticity of transactions without revealing any sensitive information. This means that the system can confirm a transaction's validity without needing to know the actual details of the transaction.

Analogy for Clarification

It's like trying to write 1500$ on a 500$ bill. Merchants would reject this bill because it does not hold the authentic value and is considered counterfeit. Similarly, if a user's balance hash does not match the recorded one, the system considers the balance to be fraudulently altered and blocks the transaction.
Simplified Process:

    User1 starts with a balance hash of 123.
    After a transaction, the balance hash becomes 456.
    This new hash (456) is recorded on the server.
    For each new transaction, the system checks that the user's current hash (before the transaction) matches the one stored on the server (456).
    If the hash differs, the transaction is blocked to prevent fraud.

This system ensures the integrity of transactions, preventing unauthorized modifications to users' balances, and enhancing security through homomorphic operations and zero-knowledge proofs.

### Install

To install `tenseal`, along with the other third-party libraries required for your project, you can use the following `pip` command:

```sh
pip install requests tenseal cryptography
```

List of the dependencies based on your imports:
### Standard Library (No need to install)
- `time`
- `argparse`
- `hashlib`
- `hmac`
- `json`
- `os`
- `logging`
- `datetime`
- `subprocess`
- `base64`
- `shutil`

### Third-Party Libraries (Install using pip)
- `requests`
- `tenseal`
- `cryptography`

### Custom Module
- `session` (Make sure this module is part of your project directory)

### Full Installation Command
```sh
pip install requests tenseal cryptography
```

### Example for Import Statements
Here’s how your import statements might look in the Python file:
```python
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
```

Ensure that you have `pip` installed and configured correctly on your system to install the required third-party libraries.


## COMMAND 
```
git clone https://github.com/ResilienceAnalytics/Electronic-Cash.git
```
```
python create_user_wallet.py --node_id YOURNAME
```

When your are ready to tx with admin:
```
python Receiver.py --transaction_amount 1 --password 'pass123' --participants YOURNAME admin
```
Select the available session and voilà.


