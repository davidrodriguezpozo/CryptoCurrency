from Transaction import *
from hashes import hashSHA1, hashSHA256

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


class User():
    """
    Fields:
        private_key
        public_key
        address: hash of the public key
        balance: number of Zimcoins
    """

    def __init__(self, name, balance):
        self.private_key = ec.generate_private_key(
            ec.SECP256K1(), default_backend())
        self.public_key = self.private_key.public_key()
        self.balance = balance
        self.nonce = 1
        self.name = name

    @property
    def address(self):
        """
        Return the public key SHA256 hash.
        """
        return hashSHA1(self.public_keyDER)

    def incr(self, amount: int):
        """
        Increase the user's balance
        """
        self.balance = self.balance + amount

    def decr(self, amount: int):
        """
        Decrease the user's balance
        """
        self.balance = self.balance - amount

    """
    Following there are some methods to obtain an encrypted version 
    of the user public and private keys in PEM and DER format
    """
    @property
    def public_keyDER(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    @property
    def public_keyPEM(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

    @property
    def private_keyDER(self):
        return self.public_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'password')).decode()

    @property
    def private_keyPEM(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b'password')).decode()

    @staticmethod
    def createTransaction(sender: 'User', recipient: 'User', amount: int, fee: int):
        """
        This static method can be used to generate transactions between two users. In order to do so, 
        it uses the method 'create_signed_transaction' described in the project specifications. 
        """
        transaction = create_signed_transaction(
            sender_private_key=sender.private_key, recipient_hash=recipient.address, amount=amount, fee=fee, nonce=sender.nonce)
        transaction.verifySignature()
        transaction.verify(sender.balance, sender.nonce-1)
        # transaction.change_balance(sender, recipient) Do this when adding the block only
        print(f"""
                Created transaction between \n {sender.public_keyPEM} and \n {recipient.public_keyPEM}. \n

                Total amount transfered: {amount}

                Signature of the transaction: {transaction.signature}

                Nonce is: {sender.nonce}

                And fee is: {fee}

                Transaction verified: {transaction.isVerified}

        """)
        return transaction


class UserState():
    """
    The USerState class is a simpler version of the User class,
    that only has two fields: balance and nonce. 
    It is used in transactions to keep track of the user's balances and nonces.
    """

    def __init__(self, balance, nonce):
        self.nonce = nonce
        self.balance = balance

    @property
    def getState(self) -> dict:
        return {self.address: self}

    def __str__(self):
        return f"""
        User State: 
        Balance: {self.balance}
        Nonce: {self.nonce}
        """


users_list = [User('Bob', 500), User('Alice', 1000), User('Charlie', 400)]

users_state = {}

for user in users_list:
    users_state[user.address] = UserState(user.balance, user.nonce)
