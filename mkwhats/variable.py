from os import MFD_CLOEXEC, pathconf_names
from donna25519.keys import PrivateKey, PublicKey

class user_enc:
    mac = b''
    enc = b''
class phone_details:
    data = {}
    def __str__(self) -> str:
        return f"<[Manufactur: {self.data.get('device_manufacturer')} AndVersion: {self.data.get('os_version')}]>"
    def __repr__(self) -> str:
        return self.__str__()
class user_session:
    clientId   = ''
    pushname   = ''
    publicKey:PublicKey = b''
    privateKey:PrivateKey = b''
    serverRef  = ''
    wid        = ''
    features   = {}
    phone      = phone_details()
    key        = user_enc()
    def __str__(self) -> str:
        return """{
    clientId    : %s
    publicKey   : %s
    privateKey  : %s
    serverRef   : %s
    enc {
        mac :   %s
        key :   %s
    }
}"""%(self.clientId, self.publicKey, self.privateKey,self.serverRef,self.key.mac, self.key.enc)
    def __repr__(self) -> str:
        return self.__str__()
class websocket_session:
    clientToken  = None
    serverToken  = None
    secret       = b''
    key_encrypted  = b''
    browserToken = None
    key_decrypted  = b''
    sharedSecret = None
    sharedSecretExpanded = b''
    me = None
    def __str__(self) -> str:
        return """{
    clientToken : %s
    serverToken : %s
    secret      : %s
    sharedSecret: %s
    me          : %s
}"""%(self.clientToken, self.serverToken, self.secret, self.sharedSecret, self.me)
    def __repr__(self) -> str:
        return self.__str__()

class Session:
    def __init__(self) -> None:
        self.user      = user_session()
        self.websocket = websocket_session()
    def __str__(self) -> str:
        return f"user {self.user.__str__()}\n weboskcet {self.websocket.__str__()}"
    def __repr__(self) -> str:
        return self.__str__()