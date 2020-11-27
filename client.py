
from cmd import Cmd
from secrets import token_hex
import json

import rpyc

from cryptography.fernet import Fernet
print("Secure RPC file system by Taikhum And Yash written in python")

kdc = rpyc.connect("localhost", 5999)


cid = token_hex(5)


fservers = kdc.root.file_servers

sym_key = Fernet.generate_key()

kdc.root.sym_key(cid, sym_key)

fc = Fernet(sym_key)

ses_key = 0

fsconn = False

fs = 0

def nsp1(cid, sid):
	global ses_key

	data = kdc.root.nsp1(cid, sid)
	data = str(fc.decrypt(bytes(data, 'utf-8')), 'utf-8')
	data = json.loads(data)

	ses_key = bytes(data['ses_key'], 'utf-8')

	return data['msg_server']

def nsp3(sid, data):
	global ses_key

	f = Fernet(ses_key)
	data = f.decrypt(bytes(data, 'utf-8'))
	rn = int(data)

	data = str(f.encrypt(bytes(str(rn + 5), 'utf-8')), 'utf-8')

	return data

def decrypt_resp(resp):
	f = Fernet(ses_key)
	data = str(f.decrypt(bytes(resp, 'utf-8')), 'utf-8')
	return data

def encrypt_params(params):
	f = Fernet(ses_key)
	data = str(f.encrypt(bytes(params, 'utf-8')), 'utf-8')
	return data

 
class MyPrompt(Cmd):
	prompt = 'CMD=>=>=> '
	def do_exit(self, inp):
		return True

	def do_ls(self, inp):
		print()
		global fs, fservers, fsconn, cid
		if fsconn:
			files = decrypt_resp(fs.root.ls(cid))
			files = json.loads(files)
			for fname in files:
				if fname.startswith('.') is False:
					print(fname)
		else:
			fservers = kdc.root.file_servers
			for key in fservers:
				print(key + '/')
		print()

	def do_cd(self, inp):
		global cid, fs, fservers, fsconn

		if inp == '..':
			if fsconn:
				fsconn = False
			return

		if fsconn:
			files = fs.root.ls()
			for fname in files:
				print(fname)
		else:
			fservers = kdc.root.file_servers
			if inp in fservers:
				# generate session key using needham schroeder protocol
				msg_server = nsp1(cid, fservers[inp])
				fs = rpyc.connect("localhost", fservers[inp])

				data = fs.root.nsp2(msg_server)

				data = nsp3(fservers[inp], data)

				resp = fs.root.nsp3(cid, data)

				if resp:
					print("Congrats on successful session key generation.")
				else:
					return

				fsconn = True
			else:
				print("Sorry MAN XXX ERROR: Directory/file does not exist.")

	def do_cat(self, inp):
		global fs, fservers, fsconn, cid
		params = json.dumps({
					'fname': inp
				})
		data = decrypt_resp(str(fs.root.cat(cid, encrypt_params(params))))
		print(data)

	def do_pwd(self, inp):
		global fs, fservers, fsconn
		print()

		if fsconn:
			data = decrypt_resp(str(fs.root.pwd(cid))) 
			print(data)
		else:
			print('/.')

		print()

	def do_cp(self, inp):
		global fs, fservers, fsconn, cid
		src, dest = inp.split(' ')
		params = json.dumps({
					'src': src,
					'dest': dest
				})
		if fsconn:
			fs.root.cp(cid, encrypt_params(params))
		else:
			print("INVALID OPERATION")
	
 
MyPrompt().cmdloop()
