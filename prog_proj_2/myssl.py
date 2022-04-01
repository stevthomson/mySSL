import base64
import secrets
import time
import hashlib
import struct
import hmac
import os
import OpenSSL.crypto
from OpenSSL import crypto 
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

'''
_______________________________________________________________

HELPER METHODS USED BY BOTH CLIENT AND SERVER IN MYSSL
_______________________________________________________________

'''


'''derrives certificate from given bytes'''
def get_cert(data):
    with open("temp.crt", "wb") as f:
        f.write(data)
    cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, open('temp.crt').read())
    return cert


'''returns the private key saved at the file path'''
def get_priv_key(path):
    data = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, open(path).read())
    return data.to_cryptography_key()


'''returns 32 bit random nonce'''
def get_nonce():
    rand_bits = secrets.randbits(256)
    milliseconds = int(round(time.time() * 1000))
    seed = str(rand_bits + milliseconds).encode('utf-8')
    nonce = int.from_bytes(hashlib.sha256(seed).digest()[:32], 'little') # 32-bit int
    return nonce


'''returns the bytes of a file at the given path'''
def read_bytes(path):
    in_file = open(path, "rb")
    data = in_file.read()
    in_file.close()
    return data


'''encrypts message using public key of given certificate'''
def cert_encrypt(msg, cert):
    key = cert.get_pubkey().to_cryptography_key()
    cipher = key.encrypt(msg,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None))
    return cipher


'''decrypts message using private key at the given path'''
def cert_decrypt(cipher_text, path):
    key = get_priv_key(path)
    return key.decrypt(cipher_text, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),label=None))


'''signs message using private key at given path'''
def sign(plain_text, path):
    key = get_priv_key(path)
    sig = key.sign(plain_text,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())
    return sig

'''verifies signature using public key of given certificate'''
def verify_sig(cert, sig, msg):
    key = cert.get_pubkey().to_cryptography_key()
    key.verify(sig, msg,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())


'''creates HMAC using messages, master secret and source (CLIENT || SERVER)'''
def keyed_hash(msgs, secret, source):
    s = b''
    for b in msgs:
        s += b
    s += source
    hash = hmac.new(secret, s, hashlib.sha1)
    return hash.digest()
    

'''if the two hashes are not the same throw value error'''
def compare_hashes(hash1, hash2):
    if hash1 != hash2:
        raise ValueError('Hashes did not match!')


'''generates new symmetric key using master secret as a password'''
def generate_key(master_secret):
    pwd = master_secret
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,iterations=390000,)
    key = base64.urlsafe_b64encode(kdf.derive(pwd))
    return key

'''driver method to return two new keys'''
def get_new_keys(k_ab):
    k_2 = generate_key(k_ab)
    k_3 = generate_key(k_ab)
    return k_2, k_3


'''encrypt using Fernet that has AES and CBC on the backend'''
def aes_encrypt(plain_text, key):
    cipher_suite = Fernet(key)
    cipher_text = cipher_suite.encrypt(plain_text)
    return cipher_text


'''decrypt using Fernet that has AES and CBC on the backend'''
def aes_decrypt(cipher_text, key):
    cipher_suite = Fernet(key)
    plain_text = cipher_suite.decrypt(cipher_text)
    return plain_text


'''encrypt using Fernet that has AES and CBC on the backend to "sign" message'''
def aes_sign(data, key):
    cipher_suite = Fernet(key)
    sig = cipher_suite.encrypt(data)
    return sig


'''decrypt using Fernet that has AES and CBC on the backend to "validate" signature'''
def aes_validate_sig(data, key, sig):
    cipher_suite = Fernet(key)
    test = cipher_suite.decrypt(sig)
    if test != data:
        raise ValueError('Invalid Signature')


'''validate self signed certificate using certificate store'''
def validate(certificate):
    cert_store = crypto.X509Store()
    cert_store.add_cert(certificate)
    store_ctx = crypto.X509StoreContext(cert_store, certificate)
    store_ctx.verify_certificate()
    print('certificate verified!')


'''helper that splits two keys and signature out of a message from either client or server'''
def get_keys_sig(data, key):
    msg = aes_decrypt(bytes(data), key)
    msg = msg.split(b'\n\n', 2)
    return msg[0], msg[1], msg[2]


#       https://docs.python.org/3.6/howto/sockets.html#using-a-socket
#       https://stackoverflow.com/questions/17667903/python-socket-receive-large-amount-of-data
#
# helper methods to send and recieve entire message given a socket (and message)

def send(sock, msg):
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)


def recieve(sock):
    msg_len = receive_all(sock, 4)
    if not msg_len:
        raise RuntimeError("socket connection broken")
    msg_len = struct.unpack('>I', msg_len)[0]
    # Read the message data
    return receive_all(sock, msg_len)


def receive_all(sock, size):
    msg = bytearray()
    received = 0
    while received < size:
        packet = sock.recv(size - received)
        if packet == b'':
            raise RuntimeError("socket connection broken")
        msg.extend(packet)
        received += len(packet)
    return msg
