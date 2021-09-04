import base64
import collections

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

from hashes import hashSHA256, hashSHA1


class Transaction():
    def __init__(self, sender_hash: bytes, recipient_hash: bytes, sender_public_key: bytes, amount: int, fee: int, nonce: int, signature: bytes, txid: bytes):
        self.sender_hash: bytes = sender_hash
        self.recipient_hash: bytes = recipient_hash
        self.sender_public_bytes: bytes = sender_public_key
        self.amount: int = amount
        self.signature: bytes = signature
        self.fee: int = fee
        self.nonce: int = nonce
        self.__verified: bool = False
        self.txid: bytes = txid
        self.sender_public_key: ec.EllipticCurvePublicKey = load_der_public_key(
            sender_public_key, default_backend())

    def __str__(self):
        text = f"""
        -------------------------------
        Transaction between {self.sender_public_bytes} and {self.recipient_hash} \n
        Amount of transaction is {self.amount}
        The signature is {self.signature}
        -------------------------------
        """
        return text

    def change_balance(self, sender, recipient):
        """
        Changes the balance of the sender and the recipient accordingly.
        """
        sender.decr(self.amount)
        recipient.incr(self.amount - self.fee)
        sender.nonce = sender.nonce + 1

    def change_user_state(self, sender, recipient) -> None:
        sender.balance = sender.balance - self.amount
        recipient.balance = recipient.balance + self.amount - self.fee
        sender.nonce = sender.nonce + 1

    def undo_user_state(self, sender, recipient) -> None:
        sender.balance = sender.balance + self.amount
        recipient.balance = recipient.balance - self.amount + self.fee
        sender.nonce = sender.nonce - 1

    def verify(self, sender_balance, sender_previous_nonce):
        """
        Verification of the transaction:
        1. Sender and recipient hash must be 20 bytes long
        2. The hashed value (with SHA1) of the sender public_key must be the sender hash
        3. Sender must have enough ZimCoins to perform the transaction
        4. Amount must be less than 2^64-1 and greater than 0
        5. Fee must be greater than 0 but less than amount
        6. Transaction ID (txid) must be equal to the obtained TXID when hashing all the fields of the transaction
        7. Signature must be verified
        """

        if len(self.sender_hash) != 20:
            raise Exception('Sender hash not 20 bytes long')
        if len(self.recipient_hash) != 20:
            raise Exception('Recipient hash not 20 bytes long!')
        assert hashSHA1(self.sender_public_bytes) == self.sender_hash

        if(sender_balance - self.amount < 0):
            raise Exception("Balance too small")

        assert self.amount > 0 and self.amount <= 2**(
            64-1), 'Amount must be positive!'
        #assert self.fee > 0 and self.fee <= self.amount, f'Fee out of bounds! Fee: {self.fee}'

        if (self.nonce != sender_previous_nonce + 1):
            raise Exception("Invalid nonce")

        if self.txid != Transaction.txid(
                self.sender_public_bytes, self.sender_hash, self.recipient_hash, Transaction.littleEndian(self.amount), Transaction.littleEndian(self.fee), Transaction.littleEndian(self.nonce), self.signature):
            raise Exception('Incorrect transaction ID!')
        # self.verifySignature()
        self.__verified = True
        return True

    @ property
    def isVerified(self):
        return self.__verified

    def verifySignature(self):
        """
        Verifies that the signature of the transaction is correct. This is, all the fields of the transaction
        and the private key of the sender are correct. 
        """
        pk = self.sender_public_key
        pk.verify(self.signature, Transaction.sig_ready(self.recipient_hash,
                                                        Transaction.littleEndian(self.amount), Transaction.littleEndian(self.fee), Transaction.littleEndian(self.nonce)), ec.ECDSA(hashes.SHA256()))

    @ staticmethod
    def sig_ready(recipient_hash: bytes, amount: int, fee: int, nonce: int) -> bytes:
        """
        Method to prepare the data to be signed by the sender's private key, and verified by their public key
        """
        msg = collections.OrderedDict(
            {'recipient_hash': recipient_hash, 'amount': amount, 'fee': fee, 'nonce': nonce})

        msg = str(msg.values()).encode('ascii')
        output_byte = base64.b64encode(msg)
        return output_byte

    @ staticmethod
    def txid(sender_public_key, sender_hash, recipient_hash, amount, fee, nonce, signature):
        """
        Obtains a transaction ID given the fields od a transaction (hashed with SHA256)
        """
        digest = hashes.Hash(hashes.SHA256())
        digest.update(sender_hash)
        digest.update(recipient_hash)
        digest.update(sender_public_key)
        digest.update(amount)
        digest.update(fee)
        digest.update(nonce)
        digest.update(signature)
        return digest.finalize()

    @ staticmethod
    def littleEndian(number: int):
        """
        Returns the bytes (with little Endian format) of the given number
        """
        return number.to_bytes(8, byteorder='little', signed=False)

    @ staticmethod
    def littleEndian16Bytes(number: int):
        """
        Returns the bytes (with little Endian format) of the given number
        """
        return number.to_bytes(16, byteorder='little', signed=False)

    @ staticmethod
    def to_dict(txid, sender_name, recipient_name, sender_public_key, recipient_public_key, signature, amount, time):
        """
        Returns an OrderDict version of the fields of the transaction
        """
        return collections.OrderedDict({
            'txid': txid,
            'sender_name': sender_name,
            'recipient_name': recipient_name,
            'sender_public_key': sender_public_key,
            'recipient_public_key': recipient_public_key,
            'signature': signature,
            'amount': amount,
            'time': time
        })

    @staticmethod
    def sign_transaction(private_key: ec.EllipticCurvePrivateKey, data: bytes):
        """
        This static method signs a transaction (passed as data) and return the signature
        obtained with the input private key. 
        """
        signature = private_key.sign(
            data, ec.ECDSA(hashes.SHA256()))
        return signature


def create_signed_transaction(sender_private_key: ec.EllipticCurvePrivateKey, recipient_hash: bytes, amount: int, fee: int = 1, nonce: int = 1) -> 'Transaction':
    """
        This is the only method that creates a transaction. It generates a valid txID and a signature, and returns a valid
        transaction, if all the values are correct.
        """
    sender_public_key = sender_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    sender_hash = hashSHA1(sender_public_key)

    # the signature contains recipient hash, amount, fee and nonce.
    signature = Transaction.sign_transaction(
        sender_private_key, Transaction.sig_ready(recipient_hash, Transaction.littleEndian(amount), Transaction.littleEndian(fee), Transaction.littleEndian(nonce)))

    txid = Transaction.txid(
        sender_public_key, sender_hash, recipient_hash, Transaction.littleEndian(amount), Transaction.littleEndian(fee), Transaction.littleEndian(nonce), signature)

    tx = Transaction(sender_hash=sender_hash, recipient_hash=recipient_hash, sender_public_key=sender_public_key,
                     amount=amount, fee=fee, nonce=nonce, txid=txid, signature=signature)
    return tx
