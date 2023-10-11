from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

class AES:
    """AES 128-bit symmetric encryption for files."""
    def __init__(self, key: bytes) -> None:
        self.__key = Fernet(key)

    @staticmethod
    def generate_key() -> bytes:
        """Returns a 128-bit key."""
        return Fernet.generate_key()

    def encrypt(self, path: str) -> None:
        """Encrypts the file located at the specified path."""
        with open(path, "rb") as f:
            file_bytes = f.read()
        with open(path, "wb") as f:
            f.write(self.__key.encrypt(file_bytes))

    def decrypt(self, path: str) -> None:
        """Decrypts the file located at the specified path."""
        with open(path, "rb") as f:
            file_bytes = f.read()
        with open(path, "wb") as f:
            f.write(self.__key.decrypt(file_bytes))

    def is_encrypted(self, path: str) -> bool:
        """Returns `True` if the file located at the specified path is encrypted using the specified key, otherwise, it returns `False`."""
        with open(path, "rb") as f:
            file_bytes = f.read()
        try:
            self.__key.decrypt(file_bytes)
        except:
            return False
        else:
            return True

class RSA:
    """
    RSA asymmetric encryption for files.

    NOTE: The RSA encryption algorithm is not recommended for operating on large files due to the large computational intensity induced by such operations, and the padding 
    overhead which increases the post-encryption file size relative to the pre-encryption file size, this can grow to be quite significant for large files.
    """
    def __init__(self, public_key: bytes | None = None, private_key: bytes | None = None) -> None:
        if not public_key and not private_key:
            raise ValueError("At least one parameter is required to be specified.")
        else:
            if public_key:
                self.__public_key = serialization.load_pem_public_key(public_key, backend=default_backend())
                self.__public_key_data_chunking_size = {284: 71, 451: 190, 800: 446}[len(public_key)]
            if private_key:
                self.__private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
                self.__private_key_data_chunking_size = {916: 128, 1704: 256, 3272: 512}[len(private_key)]

    @staticmethod
    def generate_key_pair(key_size: int) -> tuple[bytes]:
        """
        Returns a tuple containing a key pair of specified size. The first element is the public key and the second element is the private key.

        Key size options are limited to: 1024 bits, 2048 bits and 4096 bits.
        """
        if key_size != 1024 and key_size != 2048 and key_size != 4096:
            raise ValueError("Key size options are limited to: 1024, 2048 or 4096.")
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
            return (private_key.public_key().public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))

    def encrypt(self, path: str) -> None:
        """Encrypts the file located at the specified path."""
        with open(path, "rb") as f:
            file_bytes = f.read()
        with open(path, "wb") as f:
            f.write(b"".join([self.__public_key.encrypt(file_bytes[i:i+self.__public_key_data_chunking_size], padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)) for i in range(0, len(file_bytes), self.__public_key_data_chunking_size)]))

    def decrypt(self, path: str) -> None:
        """Decrypts the file located at the specified path."""
        with open(path, "rb") as f:
            file_bytes = f.read()
        with open(path, "wb") as f:
            f.write(b"".join([self.__private_key.decrypt(file_bytes[i:i+self.__private_key_data_chunking_size], padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)) for i in range(0, len(file_bytes), self.__private_key_data_chunking_size)]))
