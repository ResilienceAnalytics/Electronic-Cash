This system ensures the integrity of transactions, preventing unauthorized modifications to users' balances, and enhancing security through homomorphic operations and zero-knowledge proofs. And You really have your CASH, like a real wallet.

### Install
```sh
python3.9 -m venv myenv
source myenv/bin/activate
pip install --upgrade pip
pip install python-dotenv numpy ipfshttpclient requests cryptography pybind11
pip install tenseal
python -c "import tenseal as ts; print(ts.__version__)"
```

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
pip install numpy ipfshttpclient dotenv requests tenseal cryptography
```

Ensure that you have `pip` installed and configured correctly on your system to install the required third-party libraries.


## COMMAND 
```
git clone https://github.com/ResilienceAnalytics/Electronic-Cash.git
cd Electronic-Cash
```
```
python create_user_wallet.py --node_id YOURNAME
```

When your are ready to tx with admin:
```
python Receiver.py --transaction_amount 1 --password 'pass123' --participants YOURNAME admin

```
Select (Copy Paster Session Id) the available session and voilà.


For sending.
```
python Sender.py --transaction_amount 1 --password 'pass123' --participants YOURNAME YOURFRIEND
```


