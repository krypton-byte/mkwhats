import os
import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
# pylint: disable=invalid-name
import Crypto.Cipher.AES
import Crypto.Hash
import Crypto.Protocol
import Crypto.Util.Padding


def hkdf_expand(key: bytes, length: int) -> bytes:
    """Expand a key to a length."""
    return Crypto.Protocol.KDF.HKDF(key, length, None, Crypto.Hash.SHA256)


def validate_secrets(secret: bytes, shared_secret_expanded: bytes) -> bool:
    """Validate secrets. Used during QR login process."""
    return Crypto.Hash.HMAC.new(shared_secret_expanded[32:64],
                                secret[:32] + secret[64:],
                                Crypto.Hash.SHA256).digest() == secret[32:64]


def hmac_sha256(mac: bytes, message: bytes) -> bytes:
    """Sign a message with a mac key."""
    return Crypto.Hash.HMAC.new(mac, message, Crypto.Hash.SHA256).digest()


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt a plaintext using AES CBC."""
    plaintext = Crypto.Util.Padding.pad(plaintext,
                                        Crypto.Cipher.AES.block_size)
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC)
    ciphertext = cipher.encrypt(plaintext)
    return cipher.iv + ciphertext


def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a ciphertext using AES CBC."""
    iv = ciphertext[:Crypto.Cipher.AES.block_size]
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[Crypto.Cipher.AES.block_size:])
    return Crypto.Util.Padding.unpad(plaintext, Crypto.Cipher.AES.block_size)
def HmacSha256(key, sign):
    return hmac.new(key, sign, hashlib.sha256).digest()

def HKDF(key, length, appInfo=""):						# implements RFC 5869, some parts from https://github.com/MirkoDziadzka/pyhkdf
    key = HmacSha256("\0"*32, key)
    keyStream = ""
    keyBlock = ""
    blockIndex = 1
    while len(keyStream) < length:
        keyBlock = hmac.new(key, msg=keyBlock+appInfo+chr(blockIndex), digestmod=hashlib.sha256).digest()
        blockIndex += 1
        keyStream += keyBlock
    return keyStream[:length]

def AESPad(s):
    bs = AES.block_size
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)

def to_bytes(n, length, endianess='big'):
    h = '%x' % n
    s = ('0'*(len(h) % 2) + h).zfill(length*2).decode('hex')
    return s if endianess == 'big' else s[::-1]

def AESUnpad(s):
    return s[:-ord(s[len(s)-1:])]

def AESEncrypt(key, plaintext):							# like "AESPad"/"AESUnpad" from https://stackoverflow.com/a/21928790
    plaintext = AESPad(plaintext)
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(plaintext)

def WhatsAppEncrypt(encKey, macKey, plaintext):
    enc = AESEncrypt(encKey, plaintext)
    return HmacSha256(macKey, enc) + enc				# this may need padding to 64 byte boundary

def AESDecrypt(key, ciphertext):						# from https://stackoverflow.com/a/20868265
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    return AESUnpad(plaintext)

