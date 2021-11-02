import base64
import pyqrcode
from .variable import (
    Session
)
__all__ =['Events']
class Events:
    __all__ = ['qr']
    def __init__(self, session) -> None:
        self.session:Session = session
        self.ev_qr:list = []
    def qr(self, printed=True):
        def option(func):
            self.ev_qr.append([func, {"printed":printed}])
        return option
    def run_qr(self, printed, data, func):
        if printed:
            print(pyqrcode.create(f'{data},{base64.b32encode(self.session.user.publicKey.public).decode()},{self.session.user.clientId}').terminal(quiet_zone=1, module_color=16))
        func(data)
    def run_qr_function(self, data):
        if not self.ev_qr:
            return self.run_qr(printed=True, data=data, func=(lambda x:x))
        for i in self.ev_qr:
            self.run_qr(**i[1], data=data, func=i[0])
