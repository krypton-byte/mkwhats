from os import MFD_CLOEXEC, pathconf_names


class user_enc:
    mac = None
    enc = None
class phone_details:
    data = {}
    def __str__(self) -> str:
        return f"<[Manufactur: {self.data.get('device_manufacturer')} AndVersion: {self.data.get('os_version')}]>"
    def __repr__(self) -> str:
        return self.__str__()
class user_session:
    clientId   = None
    pushname   = None
    publicKey  = None
    privateKey = None
    serverRef  = None
    wid        = None
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
    secret       = None
    key_encrypted  = None
    browserToken = None
    key_decrypted  = None
    sharedSecret = None
    sharedSecretExpanded = None
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
class qrsetting:
    qr_color = 15
    quiet_zone = 1
    connection_isSend = False
    connection_receive = ""
class Session:
    user      = user_session()
    websocket = websocket_session()
    qr        = qrsetting()
    def __str__(self) -> str:
        return f"user {self.user.__str__()}\n weboskcet {self.websocket.__str__()}"
    def __repr__(self) -> str:
        return self.__str__()