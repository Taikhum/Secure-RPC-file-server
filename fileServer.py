import os 
import shutil
import json

from random import random

from cryptography.fernet import Fernet

sym_key = Fernet.generate_key()
fs = Fernet(sym_key)

import rpyc
print("Secure RPC file system by Taikhum And Yash written in python")

#fileserver class
class FileServer(rpyc.Service):
    def on_connect(self, conn):
        self.path = os.path.join(os.getcwd(), 'data', name)
        self.root_dir = os.path.join(os.getcwd(), 'data')
        pass



    def on_disconnect(self, conn):
        pass


    def enc_resp(self, cid, resp):
        f = Fernet(self.ses_key[cid])
        return str(f.encrypt(bytes(resp, 'utf-8')), 'utf-8')


    def dec_params(self, cid, params):
        f = Fernet(self.ses_key[cid])
        data = str(f.decrypt(bytes(params, 'utf-8')), 'utf-8')
        data = json.loads(data)
        return data


    def exposed_ls(self, cid):
        resp = json.dumps(os.listdir(self.path))
        return self.enc_resp(cid, resp)



    def exposed_cat(self, cid, params):
        txt = ""

        data = self.dec_params(cid, params)
        fname = data['fname']


        try:
            f = open(os.path.join(self.path, fname), "r")
            txt = f.read()
            f.close()
        except IOError:
            txt = "ERROR: Directory/file does not exist."
           
        return self.enc_resp(cid, txt)


    def exposed_pwd(self, cid):
        rpath =  '/' + os.path.relpath(self.path, start = self.root_dir) + '/'
        return self.enc_resp(cid, rpath)


    def exposed_cp(self, cid, params):
        f = Fernet(self.ses_key[cid])
        data = self.dec_params(cid, params)
        src = data['src']
        dest = data['dest']
        try:
            with open(os.path.join(self.path, dest), 'w') as fp: 
                pass
            shutil.copy2(os.path.join(self.path, src), os.path.join(self.path, dest)) 
        except:
            pass

    def exposed_nsp2(self, data):
        global fs
        data = json.loads(str(fs.decrypt(bytes(data, 'utf-8')), 'utf-8'))
        self.ses_key[data['cid']] = bytes(data['ses_key'], 'utf-8')
        rn = int(random() * 1000)
        self.ex_rtv[data['cid']] = rn + 5

        f = Fernet(self.ses_key[data['cid']])

        return str(f.encrypt(bytes(str(rn), 'utf-8')), 'utf-8')

    def exposed_nsp3(self, cid, data):
        f = Fernet(self.ses_key[cid])

        ern = int(str(f.decrypt(bytes(data, 'utf-8')), 'utf-8'))

        if ern == self.ex_rtv[cid]:
            return True
        else:
            return False

    ex_rtv = {}
    ses_key = {}

if __name__ == "__main__":
    print("Running...")
    print("Setting up File server")
    print("Server Connected.\n")
    name = input("Enter server name: ")
    port = int(input("Enter server port: "))

    print("____________________\n")

    kdc = rpyc.connect("localhost", 5999)
    kdc.root.register_server(name, port)

    kdc.root.sym_key(port, sym_key)

    # create fs dir

    path = os.path.join(os.getcwd(), 'data', name) 
    os.makedirs(path, exist_ok = True) 

    from rpyc.utils.server import ThreadedServer
    t = ThreadedServer(FileServer, port = port)
    t.start()

