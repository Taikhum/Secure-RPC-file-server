import json

from cryptography.fernet import Fernet

import rpyc
print("Secure RPC file system by Taikhum And Yash written in python")

class KDCService(rpyc.Service):
    def on_connect(self, conn):
        pass

    def on_disconnect(self, conn):
        # code that runs after the connection has already closed
        # (to finalize the service, if needed)
        pass

    def exposed_register_server(self, name, port):
        self.exposed_file_servers[name] = port
        print("Registered user's file server {} at port number {:d}".format(name, port))

    def exposed_sym_key(self, cid, key):
        self.sk[cid] = key

    def exposed_nsp1(self, cid, sid):
        fc = Fernet(self.sk[cid])
        fs = Fernet(self.sk[sid])
        ses_key = Fernet.generate_key()
        msg_server = fs.encrypt(bytes(json.dumps({
                                    'cid': cid,
                                    'ses_key': str(ses_key, 'utf-8')
                                }), 'utf-8'))
        data = {
            "ses_key": str(ses_key, 'utf-8'),
            "msg_server": str(msg_server, 'utf-8')
        }
        data = json.dumps(data)
        data = str(fc.encrypt(bytes(data, 'utf-8')), 'utf-8')
        return data

    sk = {}
    exposed_file_servers = {}


if __name__ == "__main__":
    from rpyc.utils.server import ThreadedServer
    t = ThreadedServer(KDCService(), port=5999)

    print("Establishing....")
    print("KDC is extablished.")
    print("Welcome.\n")

    t.start()
