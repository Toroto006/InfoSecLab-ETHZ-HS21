#!/usr/bin/env python3
from tinyec import registry, ec
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import HKDF
from Cryptodome.Signature import DSS
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.PublicKey import ECC
from typing import Tuple
import secrets

ECDH_CURVE = "secp256r1"
ECDSA_CURVE = 'P-256'
GCM_FLAG = "AESGCM"
SHA256_FLAG = "SHA256"
BLOCK_LEN = 16
MSGLEN = 20
RSA_MOD_LEN = 2048
ID_LEN = 32
NONCE_LEN = 16
EC_COORDINATE_LEN = 32
ECDSA_LEN = 64
MAC_TAG_LEN = 32
ECDSA_CTXT_LEN = 176
CLIENT_ECDSA_HELLO_SIGMA_LEN = NONCE_LEN + 2*EC_COORDINATE_LEN
SERVER_ECDSA_HELLO_SIGMA_LEN = NONCE_LEN + ID_LEN + 2*EC_COORDINATE_LEN + ECDSA_LEN + MAC_TAG_LEN
SERVER_ECDSA_HELLO_SIGMA_ID_LEN = NONCE_LEN + 2*EC_COORDINATE_LEN + ECDSA_CTXT_LEN
CLIENT_ECDSA_FIN_SIGMA_LEN = ID_LEN + ECDSA_LEN + MAC_TAG_LEN
CLIENT_ECDSA_FIN_SIGMA_ID_LEN = ECDSA_CTXT_LEN

class MacError(RuntimeError): ...
class SigError(RuntimeError): ...

class PRNG:
	def randbelow(self, number: int) -> int:
		"""Return a random int in the range [0, n)."""
		pass

	def get_random_bytes(self, nbytes: int) -> bytes:
		"""Return a random byte string containing *nbytes* bytes."""
		pass

class CryptoPRNG(PRNG):
	def randbelow(self, number: int) -> int:
		return secrets.randbelow(number) 

	def get_random_bytes(self, nbytes: int) -> bytes:
		return secrets.token_bytes(nbytes)


def convert_id(identifier: bytes) -> bytes:
	h = SHA256.new(identifier)
	hash_msg = h.digest()
	return hash_msg

def compress(pubKey: ec.Point) -> bytes:
	return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

def ec_setup(curve_name: str) -> ec.Curve:
	curve = registry.get_curve(curve_name)
	return curve

def ec_key_gen(curve: ec.Curve, prng: PRNG) -> Tuple[int, ec.Point]:
	sec_key = prng.randbelow(curve.field.n)
	pub_key = sec_key * curve.g
	return (sec_key, pub_key)

def ec_dh(sec_key: int, pub_key: ec.Point) -> ec.Point:
	shared_key = sec_key * pub_key
	return shared_key

def ecdsa_key_gen(curve_name: str, prng: PRNG) ->  Tuple[ECC.EccKey, str]:
	key = ECC.generate(curve=curve_name, randfunc=prng.get_random_bytes)
	pub_key = key.public_key()
	pub_key_pem = pub_key.export_key(format='PEM')
	return (key, pub_key_pem)

def ecdsa_sign(sec_key: ECC.EccKey, msg: bytes, prng: PRNG) -> bytes:
	h = SHA256.new(msg)
	sig = DSS.new(sec_key, 'fips-186-3', randfunc=prng.get_random_bytes)
	signature  = sig.sign(h)
	return signature

def ecdsa_verify(pub_key_pem: str, msg: bytes, signature: bytes) -> bool:
	pub_key = ECC.import_key(pub_key_pem)
	h = SHA256.new(msg)
	sig = DSS.new(pub_key, 'fips-186-3')
	try:
		sig.verify(h, signature)
		result = True
	except ValueError:
		result = False
	return result

def sigma_kdf(seed: bytes, salt: bytes) ->  Tuple[bytes, bytes, bytes]:
	mac_key, alice_key, bob_key = HKDF(seed, 32, salt, SHA256, 3)
	return (mac_key, alice_key, bob_key)

def sigma_id_kdf(seed: bytes, salt: bytes) ->  Tuple[bytes, bytes, bytes, bytes]:
	mac_key, enc_key, alice_key, bob_key = HKDF(seed, 32, salt, SHA256, 4)
	return (mac_key, enc_key, alice_key, bob_key)

def gen_mac(key: bytes, msg: bytes) -> bytes:
	hmac = HMAC.new(key, digestmod=SHA256)
	hmac.update(msg)
	tau = hmac.digest()
	return tau

def find_ptxt_pad_len(ptxt: bytes) -> int:
	message_len = len(ptxt)
	pad_len = BLOCK_LEN - (message_len % BLOCK_LEN)
	if (pad_len == 0):
		pad_len = BLOCK_LEN
	return pad_len

def add_ptxt_padding(ptxt: bytes) -> bytes:
	ptxt_set = []
	for i in range(len(ptxt)):
		ptxt_set.append(ptxt[i])
	pad_len = find_ptxt_pad_len(ptxt)
	for i in range(pad_len):
		ptxt_set.append(pad_len)
	pad_ptxt_bytes = bytes(ptxt_set)
	return pad_ptxt_bytes

def remove_ptxt_padding(ptxt: bytes) -> bytes:
	pad_ptxt_len = len(ptxt)
	pad_len = ord(chr(ptxt[pad_ptxt_len-1]))
	ptxt_len = pad_ptxt_len - pad_len
	plaintext = ptxt[:ptxt_len]
	return plaintext

def aes_gcm_enc(key: bytes, msg: bytes, ad: bytes, prng: PRNG) -> bytes:
	nonce = prng.get_random_bytes(BLOCK_LEN)
	cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
	cipher.update(ad)
	pad_msg = add_ptxt_padding(msg)
	ctxt, tag = cipher.encrypt_and_digest(pad_msg)
	nonce_ctxt_tag = nonce + tag + ctxt
	return nonce_ctxt_tag

def aes_gcm_dec(key: bytes, ctxt: bytes, ad: bytes) -> bytes:
	nonce = ctxt[:BLOCK_LEN]
	tag = ctxt[BLOCK_LEN:2*BLOCK_LEN]
	ciphertext = ctxt[2*BLOCK_LEN:]
	cipher = AES.new(key, AES.MODE_GCM, nonce)
	cipher.update(ad)
	pad_ptxt = cipher.decrypt_and_verify(ciphertext, tag)
	ptxt = remove_ptxt_padding(pad_ptxt)
	return ptxt

def parse_client_hello(msg: bytes, curve: ec.Curve) ->  Tuple[bytes, bytes, bytes, ec.Point]:
	# RECOVER client_nonce from msg
	client_nonce = msg[0:NONCE_LEN]
	# RECOVER client_x_bytes from msg
	client_x_bytes = msg[NONCE_LEN:NONCE_LEN+EC_COORDINATE_LEN]
	# RECOVER client_y_bytes from msg
	client_y_bytes = msg[NONCE_LEN+EC_COORDINATE_LEN:]
	# CONVERT X_BYTES, Y_BYTES TO client_ec_pub_key
	client_ec_pub_key = convert_x_y_bytes_ec_pub(client_x_bytes, client_y_bytes, curve=curve)
	return client_nonce, client_x_bytes, client_y_bytes, client_ec_pub_key

def parse_ecdsa_server_hello(msg: bytes, curve: ec.Curve) ->  Tuple[bytes, bytes, bytes, bytes, ec.Point, bytes, bytes]:
	# RECOVER server_nonce from msg
	server_nonce = msg[0:NONCE_LEN]
	# RECOVER server_id from msg
	server_id = msg[NONCE_LEN:NONCE_LEN+ID_LEN]
	# RECOVER server_x_bytes from msg
	server_x_bytes = msg[NONCE_LEN+ID_LEN:NONCE_LEN+ID_LEN+EC_COORDINATE_LEN]
	# RECOVER server_y_bytes from msg
	server_y_bytes = msg[NONCE_LEN+ID_LEN+EC_COORDINATE_LEN:NONCE_LEN+ID_LEN+2*EC_COORDINATE_LEN]
	# RECOVER server_signature from msg
	server_signature = msg[NONCE_LEN+ID_LEN+2*EC_COORDINATE_LEN:NONCE_LEN+ID_LEN+2*EC_COORDINATE_LEN+ECDSA_LEN]
	# RECOVER server_mac_tag from msg
	server_mac_tag = msg[NONCE_LEN+ID_LEN+2*EC_COORDINATE_LEN+ECDSA_LEN:]
	# CONVERT X_BYTES, Y_BYTES TO server_ec_pub_key
	server_ec_pub_key = convert_x_y_bytes_ec_pub(server_x_bytes, server_y_bytes, curve=curve)
	return server_nonce, server_id, server_x_bytes, server_y_bytes, server_ec_pub_key, server_signature, server_mac_tag

def parse_ecdsa_server_hello_id_hide(msg: bytes, curve: ec.Curve) ->  Tuple[bytes, bytes, bytes, ec.Point, bytes]:
	# RECOVER server_nonce from msg
	server_nonce = msg[0:NONCE_LEN]
	# RECOVER server_x_bytes from msg
	server_x_bytes = msg[NONCE_LEN:NONCE_LEN+EC_COORDINATE_LEN]
	# RECOVER server_y_bytes from msg
	server_y_bytes = msg[NONCE_LEN+EC_COORDINATE_LEN:NONCE_LEN+2*EC_COORDINATE_LEN]
	# CONVERT X_BYTES, Y_BYTE TO server_ec_pub_key 
	server_ec_pub_key = convert_x_y_bytes_ec_pub(server_x_bytes, server_y_bytes, curve)
	# RECOVER server_ctxt from msg
	server_ctxt = msg[NONCE_LEN + 2*EC_COORDINATE_LEN:]
	return server_nonce, server_x_bytes, server_y_bytes, server_ec_pub_key, server_ctxt

def parse_ecdsa_ptxt(ptxt: bytes) ->  Tuple[bytes, bytes, bytes]:
	# RECOVER identifier from ptxt
	server_id = ptxt[0:ID_LEN]
	# RECOVER signature from ptxt
	server_signature = ptxt[ID_LEN:ID_LEN+ECDSA_LEN]
	# RECOVER mac_tag from ptxt
	server_mac_tag = ptxt[ID_LEN+ECDSA_LEN:]
	return server_id, server_signature, server_mac_tag

def parse_ecdsa_client_resp(msg: bytes) ->  Tuple[bytes, bytes, bytes]:
	# RECOVER client_id from msg
	client_id = msg[0:ID_LEN]
	# RECOVER client_signature from msg
	client_signature = msg[ID_LEN:ID_LEN+ECDSA_LEN]
	# RECOVER client_mac_tag from msg
	client_mac_tag = msg[ID_LEN+ECDSA_LEN:]
	return client_id, client_signature, client_mac_tag

def convert_ec_pub_bytes(ec_pub_key: ec.Point) ->  Tuple[bytes, bytes]:
	x_int = ec_pub_key.x
	y_int = ec_pub_key.y
	x_bytes = x_int.to_bytes(EC_COORDINATE_LEN, byteorder='big')
	y_bytes = y_int.to_bytes(EC_COORDINATE_LEN, byteorder='big')
	return x_bytes, y_bytes

def convert_x_y_bytes_ec_pub(x_bytes: bytes, y_bytes: bytes, curve: ec.Curve) -> ec.Point:
	# CONVERT X_BYTES TO INT
	x_int = int.from_bytes(x_bytes, byteorder='big', signed=False)
	# CONVERT Y BYTES TO INT
	y_int = int.from_bytes(y_bytes, byteorder='big', signed=False)
	# COMPUTE EC_PUB KEY VIA ec.Point(curve, x_int, y_int)
	return ec.Point(curve, x_int, y_int)
	#return ec_pub_key

class SIGMA():

	def __init__(self, ecdsa_curve: str, ecdh_curve: str, identifier: bytes, id_hide_flag: bool, prng: PRNG=CryptoPRNG()):
		self.id = identifier
		self.ecdsa_curve = ecdsa_curve
		self.ecdh_curve = ec_setup(ecdh_curve)
		self.pub_key_dict = {}
		self.id_hide_flag = id_hide_flag
		self.prng = prng
		self.ecdsa_sec_key = None
		# Only clients objects
		self.nonce = None
		self.eph_x = None
		self.eph_y = None
		self.eph_sec_key = None
		# Only server objects
		self.mac_key = None
		self.client_key = None
		self.server_key = None
		self.client_sig_msg = None
		self.enc_key = None

	# SETUP ALG THAT PRODUCES LONG-TERM SIGNATURE KEYS
	def key_gen(self) -> str:
		# GENERATE ECDSA (sec_key, pub_key) VIA ecdsa_key_gen(self.ecdsa_curve, self.prng)
		key, pub_key_pem = ecdsa_key_gen(self.ecdsa_curve, self.prng)
		self.ecdsa_sec_key = key
		return pub_key_pem

	def register_long_term_keys(self, new_id: bytes, new_pub_key: str):
		self.pub_key_dict[new_id] = new_pub_key
	
	def get_long_term_key(self, id_pub: bytes):
		return self.pub_key_dict[id_pub]

	def client_init(self) -> bytes:
		# GENERATE A RANDOM NONCE VIA self.prng.get_random_bytes
		nonce = self.prng.get_random_bytes(NONCE_LEN)
		# GENERATE ECDH (sec_key, pub_key) via ec_key_gen(self.ecdh_curve, self.prng)
		sec_key, eph_pub_key = ec_key_gen(self.ecdh_curve, self.prng)
		# CONVERT ECDH pub_key TO BYTES VIA convert_ec_pub_bytes(eph_pub_key)
		x_bytes, y_bytes = convert_ec_pub_bytes(eph_pub_key)
		assert len(x_bytes) == EC_COORDINATE_LEN
		assert len(y_bytes) == EC_COORDINATE_LEN
		assert len(nonce) == NONCE_LEN
		self.nonce = nonce
		self.eph_x = x_bytes
		self.eph_y =y_bytes
		self.eph_sec_key = sec_key
		#CLIENT_ECDSA_HELLO_SIGMA_LEN = NONCE_LEN + 2*EC_COORDINATE_LEN
		msg = nonce + x_bytes + y_bytes
		assert len(msg) == CLIENT_ECDSA_HELLO_SIGMA_LEN
		return msg

	def server_ecdsa_resp(self, client_msg: bytes) -> bytes:
		# PARSE THE CLIENT MESSAGE TO THE FOLLOWING VALUES: client_nonce, client_x_bytes, 
		#				client_y_bytes, client_ec_pub_key
		client_nonce, client_x_bytes, client_y_bytes, client_ec_pub_key = parse_client_hello(client_msg, self.ecdh_curve)
		
		# GENERATE A RANDOM NONCE VIA self.prng.get_random_bytes
		server_nonce = self.prng.get_random_bytes(NONCE_LEN)
		# GENERATE ECDH (sec_key, pub_key) via ec_key_gen(self.ecdh_curve, self.prng)
		s_ec_pri_key, s_ec_pub_key = ec_key_gen(self.ecdh_curve, self.prng)
		# CONVERT ECDH pub_key TO BYTES VIA convert_ec_pub_bytes(eph_pub_key)
		x_bytes, y_bytes = convert_ec_pub_bytes(s_ec_pub_key)
		# PERFORM A ECDH COMPUTATION VIA ec_dh(eph_sec_key, client_ec_pub_key)
		shared_key = ec_dh(s_ec_pri_key, client_ec_pub_key)
		# CONVERT THE SECRECT EC POINT TO A BYTE REPRESENTATION VIA compress(dh_computation).encode()
		byte_shared_key = compress(shared_key).encode()
		# COMPUTE THE MESSAGE THAT THE SIGNATURE WILL BE COMPUTED OVER: c_nonce, s_nonce, c_ECDH, s_ECDH
		# that would be r_C||r_S||X||Y
		sig_msg = client_nonce + server_nonce + client_x_bytes + client_y_bytes + x_bytes + y_bytes
		# COMPUTE THE ECDSA SIGNATURE OVER THE MESSAGE USING ecdsa_sign(self.ecdsa_sec_key, sig_msg, self.prng)
		signature = ecdsa_sign(self.ecdsa_sec_key, sig_msg, self.prng)

		# salt is r_C||r_S
		salt = client_nonce + server_nonce
		if (self.id_hide_flag == True):
			# COMPUTE mac_key, enc_key, client_key, server_key USING HKDF
			self.mac_key, self.enc_key, self.client_key, self.server_key = sigma_id_kdf(byte_shared_key, salt)

		if (self.id_hide_flag == False):
			# COMPUTE mac_key, client_key, server_key VIA HKDF
			self.mac_key, self.client_key, self.server_key = sigma_kdf(byte_shared_key, salt)

		# COMPUTE THE MAC TAG OVER self.id
		mac_val = gen_mac(self.mac_key, self.id)
		# COMPUTE THE CLIENT MESSAGE THAT THE CLIENT'S SIGNATURE WILL BE COMPUTED OVER
		# Maybe r_S||r_C||Y||X
		self.client_sig_msg = server_nonce + client_nonce + x_bytes + y_bytes + client_x_bytes + client_y_bytes

		if (self.id_hide_flag == True):
			# GENERATE THE PLAINTEXT THAT WILL BE ENCRYPTED
			ptxt = self.id + signature + mac_val
			ad = server_nonce + x_bytes + y_bytes
			# ENCRYPT THE PLAINTEXT USING AES_GCM
			ctxt = aes_gcm_enc(self.enc_key, ptxt, ad, self.prng)
			# GENERATE THE SERVER SIGMA MESSAGE msg_two
			msg_two = ad + ctxt
			#SERVER_ECDSA_HELLO_SIGMA_ID_LEN = NONCE_LEN + 2*EC_COORDINATE_LEN + ECDSA_CTXT_LEN
			assert len(msg_two) == SERVER_ECDSA_HELLO_SIGMA_ID_LEN

		if (self.id_hide_flag == False):
			# GENERATE THE SERVER SIGMA MESSAGE msg_two
			msg_two = server_nonce + self.id + x_bytes + y_bytes + signature + mac_val
			#SERVER_ECDSA_HELLO_SIGMA_LEN = NONCE_LEN + ID_LEN + 2*EC_COORDINATE_LEN + ECDSA_LEN + MAC_TAG_LEN
			assert len(msg_two) == SERVER_ECDSA_HELLO_SIGMA_LEN

		return msg_two

	def client_ecdsa_resp(self, server_msg: bytes):
		if (self.id_hide_flag == True):
			# PARSE THE CLIENT MESSAGE TO THE FOLLOWING VALUES: server_nonce, server_x_bytes, 
			# 		server_y_bytes, server_eph_pub_key, server_ctxt
			server_nonce, server_x_bytes, server_y_bytes, server_ec_pub_key, server_ctxt = \
				parse_ecdsa_server_hello_id_hide(server_msg, self.ecdh_curve)

		if (self.id_hide_flag == False):
			# PARSE THE CLIENT MESSAGE TO THE FOLLOWING VALUES: server_nonce, server_id, server_x_bytes,
			#		 server_y_bytes, server_eph_pub_key, server_signature, server_mac_tag
			server_nonce, server_id, server_x_bytes, server_y_bytes, server_ec_pub_key, server_signature, server_mac_tag = \
				parse_ecdsa_server_hello(server_msg, self.ecdh_curve)

		# PERFORM A ECDH COMPUTATION VIA ec_dh(eph_sec_key, server_ec_pub_key)
		shared_key = ec_dh(self.eph_sec_key, server_ec_pub_key)
		# CONVERT THE SECRECT EC POINT TO A BYTE REPRESENTATION VIA compress(dh_computation).encode()
		byte_shared_key = compress(shared_key).encode()

		# salt is r_C||r_S
		salt = self.nonce + server_nonce

		if (self.id_hide_flag == True):
			# COMPUTE mac_key, enc_key, client_key, server_key USING HKDF
			mac_key, enc_key, client_key, server_key = sigma_id_kdf(byte_shared_key, salt)
			# DECRYPT THE PLAINTEXT WITH aes_gcm_dec(..., ..., 
			# 				server_nonce + server_x_bytes + server_y_bytes)
			ptxt = aes_gcm_dec(enc_key, server_ctxt, server_nonce + server_x_bytes + server_y_bytes)
			# PARSE THE PLAINTEXT TO: server_id, server_signature, server_mac_tag
			server_id, server_signature, server_mac_tag = parse_ecdsa_ptxt(ptxt)
		
		assert len(server_mac_tag) == MAC_TAG_LEN

		if (self.id_hide_flag == False):
			# COMPUTE mac_key, client_key, server_key USING HKDF
			mac_key, client_key, server_key = sigma_kdf(byte_shared_key, salt)

		# RECOVER THE SERVER ECDSA PUBLIC KEY FROM DICTIONARY USING server_id
		pub_key_pem = self.get_long_term_key(server_id)
		# COMPUTE THE MESSAGE THAT THE SIGNATURE WAS BE COMPUTED OVER: 
		#				c_nonce, s_nonce, c_ECDH, s_ECDH == server_sig_msg
		# that would be r_C||r_S||X||Y
		server_sig_msg = self.nonce + server_nonce + self.eph_x + self.eph_y + server_x_bytes + server_y_bytes
		# VERIFY THE SIGNATURE WITH ecdsa_verify(...)
		# very not sure about server_ec_pub_key 
		result = ecdsa_verify(pub_key_pem, server_sig_msg, server_signature)

		if (result == False):
			raise SigError("Signature Verification Failed!")

		# GENERATE MAC TAG OVER server_id
		mac_tag_prime = gen_mac(mac_key, server_id)

		if (mac_tag_prime != server_mac_tag):
			raise MacError("MAC Verification Failed!")

		# COMPUTE THE MESSAGE THAT THE SIGNATURE WILL BE COMPUTED OVER:
		# 			s_nonce, c_nonce, s_ECDH c_ECDH
		sig_msg = server_nonce + self.nonce + server_x_bytes + server_y_bytes + self.eph_x + self.eph_y
		# COMPUTE THE SIGNATURE USING ecdsa_sign(self.ecdsa_sec_key, sig_msg, self.prng)
		signature = ecdsa_sign(self.ecdsa_sec_key, sig_msg, self.prng)
		# GENERATE MAC TAG OVER self.id
		mac_tag = gen_mac(mac_key, self.id)

		if (self.id_hide_flag == True):
			# GENERATE PLAINTEXT 
			ptxt = self.id + signature + mac_tag
			# ENCRYPT PLAINTEXT USING aes_gcm_enc(enc_key, ptxt, "Finished".encode(), self.prng)
			ctxt = aes_gcm_enc(enc_key, ptxt, "Finished".encode(), self.prng)
			msg_three = ctxt
			#CLIENT_ECDSA_FIN_SIGMA_ID_LEN = ECDSA_CTXT_LEN
			assert len(msg_three) == CLIENT_ECDSA_FIN_SIGMA_ID_LEN

		if (self.id_hide_flag == False):
			# SET msg_three = id + ec_signature + mac_tag
			msg_three = self.id + signature + mac_tag
			#CLIENT_ECDSA_FIN_SIGMA_LEN = ID_LEN + ECDSA_LEN + MAC_TAG_LEN
			assert len(msg_three) == CLIENT_ECDSA_FIN_SIGMA_LEN

		return msg_three, client_key, server_key

	def server_ecdsa_fin(self, client_msg: bytes):
		if (self.id_hide_flag == True):
			# DECRYPT MESSAGE VIA aes_gcm_dec(..., ..., "Finished".encode())
			ptxt = aes_gcm_dec(self.enc_key, client_msg, "Finished".encode())
			# PARSE THE PLAINTEXT VIA INTO
			#	client_id, client_signature, client_mac_tag
			client_id, client_signature, client_mac_tag = parse_ecdsa_client_resp(ptxt)

		if (self.id_hide_flag == False):
			# PARSE THE MESSAGE INTO
			#	client_id, client_signature, client_mac_tag
			client_id, client_signature, client_mac_tag = parse_ecdsa_client_resp(client_msg)

		# RECOVER THE PUBLIC KEY FROM DICTIONARY USING client_id
		pub_key_pem = self.get_long_term_key(client_id)
		# VERIFY THE SIGNATURE WITH ecdsa_verify(...)
		result = ecdsa_verify(pub_key_pem, self.client_sig_msg, client_signature)

		if (result == False):
			raise SigError("Signature Verification Failed!")
		
		# GENERATE MAC TAG OVER client_id
		mac_tag_prime = gen_mac(self.mac_key, client_id)
		
		if (mac_tag_prime != client_mac_tag):
			raise MacError("MAC Verification Failed!")
		
		return self.client_key, self.server_key

if __name__ == "__main__":
	bob_id = convert_id("bob".encode())
	alice_id = convert_id("alice".encode())
	ID_HIDE_FLAG = False
	#ID_HIDE_FLAG = True
	alice_sigma = SIGMA(ECDSA_CURVE, ECDH_CURVE, alice_id, ID_HIDE_FLAG)
	bob_sigma = SIGMA(ECDSA_CURVE, ECDH_CURVE, bob_id, ID_HIDE_FLAG)
	alice_ec_pub_key = alice_sigma.key_gen()
	bob_ec_pub_key = bob_sigma.key_gen()
	alice_sigma.register_long_term_keys(bob_id, bob_ec_pub_key)
	alice_sigma.register_long_term_keys(alice_id, alice_ec_pub_key)
	bob_sigma.register_long_term_keys(bob_id, bob_ec_pub_key)
	bob_sigma.register_long_term_keys(alice_id, alice_ec_pub_key)
	msg = alice_sigma.client_init()
	msg_two = bob_sigma.server_ecdsa_resp(msg)
	msg_three, client_alice_key, client_bob_key = alice_sigma.client_ecdsa_resp(msg_two)
	server_alice_key, server_bob_key = bob_sigma.server_ecdsa_fin(msg_three)
	if ((client_alice_key == server_alice_key) and (client_bob_key == server_bob_key)):
		print("Both parties computed the same key")
	else:
		print("Something went wrong")