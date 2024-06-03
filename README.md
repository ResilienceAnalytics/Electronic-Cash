This system ensures the integrity of transactions, preventing unauthorized modifications to users' balances, and enhancing security through homomorphic operations and zero-knowledge proofs. And You really have your CASH, like a real wallet.

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

### Full Installation Command
```sh
pip install requests tenseal cryptography
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

For sending.
```
python Sender.py --transaction_amount 1 --password 'pass123' --participants YOURNAME YOURFRIEND
```


