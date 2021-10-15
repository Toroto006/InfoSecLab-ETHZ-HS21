#!/usr/bin/env python

'''
tls_crypto.py:
Contains various cryptographic functions needed during handshake and record protocols
'''

import hmac
from math import ceil
from tinyec import registry, ec
import secrets
import binascii
from tls_constants import *
from tls_error import *
from Cryptodome.Cipher import AES, ChaCha20_Poly1305
from Cryptodome.Hash import HMAC, SHA256, SHA384
from Cryptodome.Signature import pkcs1_15, DSS
from Cryptodome.PublicKey import RSA, ECC


def xor_bytes(bytes_one, bytes_two):
	xor_len = len(bytes_two)
	int_one = int.from_bytes(bytes_one, 'big')
	int_two = int.from_bytes(bytes_two, 'big')
	int_xor = int_one ^ int_two
	return int_xor.to_bytes(xor_len, 'big')

def compress(pubKey):
	return hex(pubKey.x) + hex(pubKey.y % 2)[2:]

def point_to_secret(pubKey, group):
	secret = pubKey.x.to_bytes(tls_constants.COORD_LEN[group], 'big')
	return secret

def ec_setup(curve_name):
	curve = registry.get_curve(curve_name)
	return curve

def ec_key_gen(curve):
	sec_key = secrets.randbelow(curve.field.n)
	pub_key = sec_key * curve.g
	return (sec_key, pub_key)

def ec_dh(sec_key, pub_key):
	shared_key = sec_key * pub_key
	return shared_key

def convert_ec_pub_bytes(ec_pub_key, group_name):
	x_int = ec_pub_key.x
	y_int = ec_pub_key.y
	x_bytes = x_int.to_bytes(tls_constants.COORD_LEN[group_name], byteorder='big')
	y_bytes = y_int.to_bytes(tls_constants.COORD_LEN[group_name], byteorder='big')
	return x_bytes + y_bytes

def convert_x_y_bytes_ec_pub(pub_bytes, group_name):
	x_bytes = pub_bytes[:tls_constants.COORD_LEN[group_name]]
	y_bytes = pub_bytes[tls_constants.COORD_LEN[group_name]:]
	x_int = int.from_bytes(x_bytes, byteorder='big')
	y_int = int.from_bytes(y_bytes, byteorder='big')
	curve = ec_setup(tls_constants.GROUP_FLAGS[group_name])
	ec_pub_key = ec.Point(curve, x_int, y_int)
	return ec_pub_key

def get_rsa_pk_from_cert(cert_string):
	public_key = RSA.import_key(cert_string)
	return public_key

def get_ecdsa_pk_from_cert(cert_string):
	public_key = ECC.import_key(cert_string)
	return public_key

class HKDF:
	def __init__(self, csuite):
		self.csuite = csuite 
		if (self.csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (self.csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
			hash=SHA256.new()
		if (self.csuite == tls_constants.TLS_AES_256_GCM_SHA384):
			hash=SHA384.new()
		self.hash_length = hash.digest_size

	def tls_hkdf_extract(self, input_key_material, salt):
		if (self.csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (self.csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
			hash=SHA256.new()
		else:
			hash=SHA384.new()
		if (salt == None):
			salt = b'\0' * (self.hash_length)
		if (input_key_material == None):
			input_key_material = b'\0' * (self.hash_length)
		ex_secret = hmac.new(salt, input_key_material, hash).digest()
		return ex_secret

	def tls_hkdf_expand(self, secret, info, length):
		if (self.csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (self.csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
			hash=SHA256.new()
		else:
			hash=SHA384.new()
		ex_secret = hmac.new(secret, info+bytes([1]), hash).digest()
		return ex_secret[:length]

def tls_transcript_hash(csuite, context):
	if csuite == TLS_AES_128_GCM_SHA256 or csuite == TLS_CHACHA20_POLY1305_SHA256:
		# SHA256
		hash_object = SHA256.new(data=context)
		SHA_LEN = SHA_256_LEN
	if csuite == TLS_AES_256_GCM_SHA384:
		# SHA384
		hash_object = SHA384.new(data=context)
		SHA_LEN = SHA_384_LEN
	
	# Do the things for both
	hash_object.digest_size = SHA_LEN # not sure if this is the corret way, but passes test?
	digest = hash_object.digest()
	assert len(digest) == SHA_LEN
	return digest

def tls_hkdf_label(label, context, length: int):
	# CONVERT BYTES TO INT and back
	#x_int = int.from_bytes(x_bytes, byteorder='big', signed=False)
	#x_bytes = x_int.to_bytes(EC_COORDINATE_LEN, byteorder='big')
	len_bytes = length.to_bytes(2, byteorder='big')
	assert len(label) <= 255-7
	label_bytes = b"tls13 "+label
	label_size = (len(label_bytes)).to_bytes(1, byteorder='big')
	assert len(context) <= 255
	context_size = (len(context)).to_bytes(1, byteorder='big')
	hkdf_label = len_bytes + label_size + label_bytes + context_size + context
	assert len(hkdf_label) == 2+(1+6+len(label))+(1+len(context))
	return hkdf_label

def tls_derive_key_iv(csuite, secret):
	hkdf = HKDF(csuite)
	#[sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
	hkdf_label_key = tls_hkdf_label(b"key", b"", KEY_LEN[csuite])
	key = hkdf.tls_hkdf_expand(secret, hkdf_label_key, KEY_LEN[csuite])
	#hkdf = HKDF(csuite)
	#[sender]_write_iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
	hkdf_label_iv = tls_hkdf_label(b"iv", b"", KEY_LEN[csuite])
	iv = hkdf.tls_hkdf_expand(secret, hkdf_label_iv, KEY_LEN[csuite])
	return key, iv # bytes

def tls_extract_secret(csuite, keying_material, salt):
	if csuite == TLS_AES_128_GCM_SHA256 or csuite == TLS_CHACHA20_POLY1305_SHA256:
		pass
	if csuite == TLS_AES_256_GCM_SHA384:
		pass
	raise NotImplementedError()

def tls_derive_secret(csuite, secret, label, messages):
	raise NotImplementedError()

def tls_finished_key_derive(csuite, secret):
	raise NotImplementedError()

def tls_finished_mac(csuite, key, context):
	raise NotImplementedError()

def tls_finished_mac_verify(csuite, key, context, tag):
	raise NotImplementedError()

def tls_nonce(csuite, sqn_no, iv):
	raise NotImplementedError()

def tls_aead_encrypt(csuite, key, nonce, plaintext):
	raise NotImplementedError()

def tls_aead_decrypt(csuite, key, nonce, ciphertext):
	raise NotImplementedError()

def tls_signature_context(context_flag, content):
	raise NotImplementedError()

def tls_signature(signature_algorithm, msg, context_flag):
	raise NotImplementedError()

def tls_verify_signature(signature_algorithm, message, context_flag, signature, public_key):
	raise NotImplementedError()