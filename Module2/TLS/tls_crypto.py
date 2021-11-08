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

def hkdf_expand_label(csuite, secret, label, context, length):
	hkdf = HKDF(csuite)
	hkdf_label_key = tls_hkdf_label(label, context, length)
	return hkdf.tls_hkdf_expand(secret, hkdf_label_key, length)

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
	#assert len(digest) == SHA_LEN
	return digest

def tls_hkdf_label(label, context, length: int):
	# CONVERT BYTES TO INT and back
	#x_int = int.from_bytes(x_bytes, byteorder='big', signed=False)
	#x_bytes = x_int.to_bytes(EC_COORDINATE_LEN, byteorder='big')
	len_bytes = length.to_bytes(2, byteorder='big')
	label_bytes = b"tls13 "+label
	if not (7 <= len(label_bytes) <= 255):
		print(f"The label for tls_hkdf_label is of the wrong size: {len(label)}")
		raise WrongLengthError()
	label_size = (len(label_bytes)).to_bytes(1, byteorder='big')
	#assert len(context) <= 255
	context_size = (len(context)).to_bytes(1, byteorder='big')
	hkdf_label = len_bytes + label_size + label_bytes + context_size + context
	#assert len(hkdf_label) == 2+(1+6+len(label))+(1+len(context))
	return hkdf_label

def tls_derive_key_iv(csuite, secret):
	#[sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
	key = hkdf_expand_label(csuite, secret, b"key", b"", KEY_LEN[csuite])
	#[sender]_write_iv = HKDF-Expand-Label(Secret, "iv", "", iv_length)
	iv = hkdf_expand_label(csuite, secret, b"iv", b"", IV_LEN[csuite])
	return key, iv # bytes

def tls_extract_secret(csuite, keying_material, salt):
	# keying material – a series of secret (potentially non-uniform) bytes --> still passes tests
	hkdf = HKDF(csuite)
	secret = hkdf.tls_hkdf_extract(keying_material, salt)
	return secret

def tls_derive_secret(csuite, secret, label, messages):
	transcript_hash = tls_transcript_hash(csuite, messages)
	secret = hkdf_expand_label(csuite, secret, label, transcript_hash, len(transcript_hash))
	return secret

def tls_finished_key_derive(csuite, secret):
	#finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
	if csuite == TLS_AES_128_GCM_SHA256 or csuite == TLS_CHACHA20_POLY1305_SHA256:
		hashlen = SHA_256_LEN
	if csuite == TLS_AES_256_GCM_SHA384:
		hashlen = SHA_384_LEN 
	finished_key = hkdf_expand_label(csuite, secret, b"finished", b"", hashlen) # len secet = Hash.len??
	return finished_key

def tls_finished_mac(csuite, key, context):
	if csuite == TLS_AES_128_GCM_SHA256 or csuite == TLS_CHACHA20_POLY1305_SHA256:
		h = HMAC.new(key, digestmod=SHA256)
	if csuite == TLS_AES_256_GCM_SHA384:
		h = HMAC.new(key, digestmod=SHA384)
	h.update(context)
	verify_data = h.digest() # Size looks correct and also digest (instead of hexdigest)
	return verify_data

def tls_finished_mac_verify(csuite, key, context, tag):
	# throws a value error??
	if csuite == TLS_AES_128_GCM_SHA256 or csuite == TLS_CHACHA20_POLY1305_SHA256:
		h = HMAC.new(key, digestmod=SHA256)
	if csuite == TLS_AES_256_GCM_SHA384:
		h = HMAC.new(key, digestmod=SHA384)
	h.update(context)
	h.verify(tag)

def tls_nonce(csuite, sqn_no, iv):
	# The per-record nonce for the AEAD construction is formed as follows:
	# 1. The 64-bit record sequence number is encoded in network byte order and padded to the
	# left with zeros to iv_length.
	sqn_no_bytes = sqn_no.to_bytes(8, byteorder='big')
	padding = IV_LEN[csuite]-len(sqn_no_bytes)
	assert padding >= 0
	sqn_no_bytes = b'\x00'*padding + sqn_no_bytes
	# 2. The padded sequence number is XORed with either the static client_write_iv
	assert len(sqn_no_bytes) == len(iv)
	xord_sqn_no = xor_bytes(sqn_no_bytes, iv)
	# The resulting quantity (of length iv_length) is used as the per-record nonce
	return xord_sqn_no

def tls_aead_encrypt(csuite, key, nonce, plaintext):
	if len(plaintext) > 2**14 + 255:
		#  the full encoded TLSInnerPlaintext MUST NOT exceed 2^14 + 1 octets
		raise WrongLengthError(f"In tls_aead_encrypt the plaintext (size: {len(plaintext)}) is bigger than 2**14 + 256.")

	# The length of the AEAD output will generally be larger than the plaintext, but by an amount that varies with the AEAD algorithm
	if csuite == TLS_CHACHA20_POLY1305_SHA256:
		ctxt_len = len(plaintext) #  The output is an encrypted message, or "ciphertext", of the same length.
	if csuite == TLS_AES_256_GCM_SHA384:
		ctxt_len = len(plaintext) # for AES the case, https://crypto.stackexchange.com/questions/26783/ciphertext-and-tag-size-and-iv-transmission-with-aes-in-gcm-mode
	if csuite == TLS_AES_128_GCM_SHA256:
		ctxt_len = len(plaintext) # ask lucas if he also got to this result --> yes
	#additional_data = TLSCiphertext.opaque_type || TLSCiphertext.legacy_record_version || TLSCiphertext.length
	ad = APPLICATION_TYPE.to_bytes(1, byteorder='big') \
		+ LEGACY_VERSION.to_bytes(2, byteorder='big') \
		+ (ctxt_len+16).to_bytes(2, byteorder='big')

	# Use AEAD for enc:
	if csuite == TLS_CHACHA20_POLY1305_SHA256:
		# >>> header = b"header"
		# >>> plaintext = b'Attack at dawn'
		# >>> key = get_random_bytes(32)
		cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
	if csuite == TLS_AES_256_GCM_SHA384 or csuite == TLS_AES_128_GCM_SHA256:
		# >>> header = b"header"
		# >>> data = b"secret"
		# >>> key = get_random_bytes(16)
		cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN[csuite])

	cipher.update(ad)
	encrypted_record, tag = cipher.encrypt_and_digest(plaintext)
	ciphertext = encrypted_record + tag 
	return ciphertext

def tls_aead_decrypt(csuite, key, nonce, ciphertext):
	#additional_data = TLSCiphertext.opaque_type || TLSCiphertext.legacy_record_version || TLSCiphertext.length
	ad = APPLICATION_TYPE.to_bytes(1, byteorder='big') \
		+ LEGACY_VERSION.to_bytes(2, byteorder='big') \
		+ len(ciphertext).to_bytes(2, byteorder='big')
	if csuite == TLS_CHACHA20_POLY1305_SHA256:
		cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
	if csuite == TLS_AES_256_GCM_SHA384 or csuite == TLS_AES_128_GCM_SHA256:
		cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=MAC_LEN[csuite])
	cipher.update(ad)
	ctxt = ciphertext[:-16]
	mac_tag = ciphertext[-16:]
	plaintext = cipher.decrypt_and_verify(ctxt, mac_tag)
	return plaintext

def tls_signature_context(context_flag, content):
	if context_flag == SERVER_FLAG:
		context_bytes = b"TLS 1.3, server CertificateVerify"
	if context_flag == CLIENT_FLAG:
		context_bytes = b"TLS 1.3, client CertificateVerify"
	
	message = b'\x20'*64 + context_bytes + b'\x00' + content
	return message
	
def tls_signature(signature_algorithm, msg, context_flag):
	message = tls_signature_context(context_flag, msg)
	
	#h = SHA256.new(message)
	if signature_algorithm == RSA_PKCS1_SHA256:
		key = RSA2048_KEY
		sha = SHA256.new(message)
		signature = pkcs1_15.new(key).sign(sha)
	if signature_algorithm == RSA_PKCS1_SHA384:
		key = RSA2048_KEY
		sha = SHA384.new(message)
		signature = pkcs1_15.new(key).sign(sha)
	if signature_algorithm == ECDSA_SECP384R1_SHA384:
		key = SECP384R1_KEY
		sha = SHA384.new(message)
		signature = DSS.new(key, 'fips-186-3').sign(sha)
	return signature

def tls_verify_signature(signature_algorithm, message, context_flag, signature, public_key):
	message = tls_signature_context(context_flag, message)
	
	#h = SHA256.new(message)
	if signature_algorithm == RSA_PKCS1_SHA256:
		sha = SHA256.new(message)
		signature = pkcs1_15.new(public_key).verify(sha, signature)
	if signature_algorithm == RSA_PKCS1_SHA384:
		sha = SHA384.new(message)
		signature = pkcs1_15.new(public_key).verify(sha, signature)
	if signature_algorithm == ECDSA_SECP384R1_SHA384:
		sha = SHA384.new(message)
		signature = DSS.new(public_key, 'fips-186-3').verify(sha, signature)
	