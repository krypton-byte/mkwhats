from mkwhats.connection import websocket_connection
whatsapp=websocket_connection(user_agent='Chrome')

@whatsapp.on.qr(printed=False)
def scan(data):
    print({'data_qr':data})

whatsapp.connect()
