Proof Of Concept with vulnerabilty

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


