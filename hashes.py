from cryptography.hazmat.primitives import hashes


def hashSHA1(obj: bytes):
    """
    This static method hashes a value using the SHA1 algorithm
    """
    digest = hashes.Hash(hashes.SHA1())
    digest.update(obj)
    return digest.finalize()


def hashSHA256(obj: bytes):
    """
    This static method hashes a value using the SHA1 algorithm
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(obj)
    return digest.finalize()
