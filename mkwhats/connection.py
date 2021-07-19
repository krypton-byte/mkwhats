import websockets
from .BinaryReader import whatsappReadBinary
import pyqrcode
import json
import re
import time
import datetime
import base64
import os
import websocket
from .variable import Session
import donna25519
import threading
from .exceptions import HmacValidatorError
from .endecrytor import (
    hkdf_expand,
    hmac_sha256,
    HmacSha256,
    aes_decrypt,
    aes_encrypt,
    AESPad,
    AESUnpad,
    AESDecrypt,
    AESEncrypt,
    WhatsAppEncrypt,
    to_bytes,
    validate_secrets
)
prefix_list = ("Conn", "Presence", "MsgInfo")
class websocket_connection:
    session=Session()
    def __init__(self) -> None:
        pass
    def connect(self, user_agent:str) -> None:
        self.user_agent = user_agent
        self.example_data = None
        self.isLogin = False
        self.user_agent = user_agent
        self.session.user.clientId = base64.b64encode(os.urandom(16)).decode()
        self.websocket = websocket.create_connection("wss://web.whatsapp.com/ws", header={"Origin: https://web.whatsapp.com"})
        self.session.user.privateKey = donna25519.PrivateKey()
        self.session.user.publicKey = self.session.user.privateKey.get_public()
        self.session.websocket.sharedSecret = self.session.user.privateKey.do_exchange(self.session.user.publicKey)
        threading.Thread(target=self.recv_websocket, args=()).start()
    def recv_websocket(self):
        while True:
            try:
                receive = self.websocket.recv()
                print(receive)
                if isinstance(receive, bytes):
                    if HmacSha256(self.session.user.key.mac, receive[32:]) != receive[:32]:
                        raise HmacValidatorError("Hmac mismatch")
                    else:
                        decMsg=AESDecrypt(self.session.user.key.enc, receive[32:])
                        try:
                            pdata = whatsappReadBinary(decMsg, True)
                            self.example_data = pdata
                            print(pdata)
                            print(pdata)
                        except Exception as e:
                            print(e)
                else:
                    prefix, data = receive.split(",", 1)
                    if re.match("s[0-9]",prefix):
                        recv = json.loads(data)
                        if recv[0] == "Conn" and not self.isLogin:
                            self.isLogin = True
                            self.session.user.serverRef         = recv[1]["ref"]
                            self.session.user.wid               = recv[1]["wid"]
                            self.session.websocket.serverToken  = recv[1]["serverToken"]
                            self.session.websocket.clientToken  = recv[1]["clientToken"]
                            self.session.websocket.browserToken = recv[1]["browserToken"]
                            self.session.websocket.secret       = base64.b64decode(recv[1]["secret"].encode())
                            self.session.websocket.sharedSecret = self.session.user.privateKey.do_exchange(donna25519.PublicKey(self.session.websocket.secret[:32]))
                            self.session.websocket.sharedSecretExpanded = hkdf_expand(self.session.websocket.sharedSecret, 80)
                            self.session.user.features         = recv[1]["features"]
                            self.session.user.phone.data       = recv[1]["phone"]
                            self.session.user.pushname         = recv[1]["pushname"]
                            if not validate_secrets(self.session.websocket.secret, self.session.websocket.sharedSecretExpanded):
                                raise HmacValidatorError("Hmac Validate Error")
                            self.session.websocket.key_encrypted = self.session.websocket.sharedSecretExpanded[64:]+self.session.websocket.secret[64:]
                            self.session.websocket.key_decrypted = aes_decrypt(self.session.websocket.sharedSecretExpanded[:32], self.session.websocket.key_encrypted)
                            self.session.user.key.enc = self.session.websocket.key_encrypted[:32]
                            self.session.user.key.mac = self.session.websocket.key_decrypted[32:64]
                            print(f"LOGIN as {self.session.user.pushname}")
                        else:
                            data=json.loads(data)
                            print(json.dumps(data, indent=4))
                    elif re.match("[0-9]{0,12},", receive): # qr detected
                        print("QR")
                        self.session.qr.connection_receive = json.loads(re.search(",(\{\".*?\}$)",receive).group(1))
            except Exception as e:
                self.connect(self.user_agent)
                break

    def get_qr(self, quiet_zone=1, qr_color=16):
        self.session.qr.quiet_zone = quiet_zone
        self.session.qr.qr_color = qr_color
        self.session.qr.connection_receive = ""
        self.session.qr.connection_isSend = True
        self.websocket.send(int(time.time()).__str__()+f',["admin", "init", [2, 7212, 10], ["{self.user_agent} at {datetime.datetime.now().isoformat()}", "{self.user_agent}"], "{self.session.user.clientId}", true]')
        while True:
            if self.session.qr.connection_receive:
                self.session.qr.connection_isSend = False
                return pyqrcode.create(f"{self.session.qr.connection_receive['ref']},{base64.b64encode(self.session.user.publicKey.public).decode()},{self.session.user.clientId}").terminal(quiet_zone=quiet_zone, module_color=qr_color)
    def logout(self):
        self.websocket.send('goodbye,,["admin","Conn","disconnect"]')