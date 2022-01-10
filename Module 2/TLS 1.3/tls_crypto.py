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
		h = SHA256.new(context)
	elif csuite == TLS_AES_256_GCM_SHA384:
		h = SHA384.new(context)

	transcript_hash = h.digest()
	return transcript_hash

def tls_hkdf_label(label, context, length):
	# Encode the lengths
	length_bytes = length.to_bytes(2, byteorder='big')
	label_len = len("tls13 ".encode() + label)
	label_length_bytes = label_len.to_bytes(1, byteorder='big') # Why is this 1?
	context_len = len(context)
	context_length_bytes = context_len.to_bytes(1, byteorder='big')

	return length_bytes + label_length_bytes + "tls13 ".encode() + label + context_length_bytes + context

def tls_derive_key_iv(csuite, secret):
	hkdf = HKDF(csuite)
	key_label = tls_hkdf_label("key".encode(), "".encode(), KEY_LEN[csuite])
	iv_label = tls_hkdf_label("iv".encode(), "".encode(), IV_LEN[csuite])

	key = hkdf.tls_hkdf_expand(secret, key_label, KEY_LEN[csuite])
	iv = hkdf.tls_hkdf_expand(secret, iv_label, IV_LEN[csuite])

	return key, iv

def tls_extract_secret(csuite, keying_material, salt):
	hkdf = HKDF(csuite)
	secret = hkdf.tls_hkdf_extract(keying_material, salt)

	return secret

def tls_derive_secret(csuite, secret, label, messages):
	hkdf = HKDF(csuite)
	hash = tls_transcript_hash(csuite, messages)
	hash_length = SHA_384_LEN if csuite == TLS_AES_256_GCM_SHA384 else SHA_256_LEN
	secret_label = tls_hkdf_label(label, hash, hash_length)
	secret = hkdf.tls_hkdf_expand(secret, secret_label, hash_length)

	return secret

def tls_finished_key_derive(csuite, secret):
	hkdf = HKDF(csuite)
	hash_length = SHA_384_LEN if csuite == TLS_AES_256_GCM_SHA384 else SHA_256_LEN
	label = tls_hkdf_label("finished".encode(), "".encode(), hash_length)
	finished_key = hkdf.tls_hkdf_expand(secret, label, hash_length)

	return finished_key

def tls_finished_mac(csuite, key, context):
	if csuite == TLS_AES_256_GCM_SHA384:
		hmac = HMAC.new(key, context, SHA384)
	else:
		hmac = HMAC.new(key, context, SHA256)

	finished_tag = hmac.digest()
	return finished_tag

def tls_finished_mac_verify(csuite, key, context, tag):
	if csuite == TLS_AES_256_GCM_SHA384:
		hmac = HMAC.new(key, context, SHA384)
	else:
		hmac = HMAC.new(key, context, SHA256)

	hmac.verify(tag)

def tls_nonce(csuite, sqn_no, iv):
	sqn_no_bytes = sqn_no.to_bytes(IV_LEN[csuite], byteorder='big')
	nonce = xor_bytes(sqn_no_bytes, iv)

	return nonce

def tls_aead_encrypt(csuite, key, nonce, plaintext):
	# Create the cipher
	if csuite == TLS_CHACHA20_POLY1305_SHA256:
		cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
	else:
		cipher = AES.new(key, AES.MODE_GCM, nonce)

	# Create the additional data for authentication
	app_type_bytes = APPLICATION_TYPE.to_bytes(CONTENT_TYPE_LEN, byteorder='big')
	legacy_type_bytes = LEGACY_VERSION.to_bytes(PROTOCOL_VERSION_LEN, byteorder='big')
	len_bytes = (len(plaintext) + MAC_LEN[csuite]).to_bytes(RECORD_LENGTH_LEN, byteorder='big') # incorrect
	additional_data = app_type_bytes + legacy_type_bytes + len_bytes
	cipher.update(additional_data)

	# Encrypt the plaintext
	ctxt, tag = cipher.encrypt_and_digest(plaintext)

	return ctxt + tag

def tls_aead_decrypt(csuite, key, nonce, ciphertext):
	# Create the cipher
	if csuite == TLS_CHACHA20_POLY1305_SHA256:
		cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
	else:
		cipher = AES.new(key, AES.MODE_GCM, nonce)

	# Create the additional data for authentication
	app_type_bytes = APPLICATION_TYPE.to_bytes(CONTENT_TYPE_LEN, byteorder='big')
	legacy_type_bytes = LEGACY_VERSION.to_bytes(PROTOCOL_VERSION_LEN, byteorder='big')
	len_bytes = len(ciphertext).to_bytes(RECORD_LENGTH_LEN, byteorder='big')
	additional_data = app_type_bytes + legacy_type_bytes + len_bytes
	cipher.update(additional_data)

	# Decrypty and Verify the ciphertext
	ctxt_length = len(ciphertext) - MAC_LEN[csuite]
	ctxt = ciphertext[0:ctxt_length]
	tag = ciphertext[ctxt_length:]
	plaintext = cipher.decrypt_and_verify(ctxt, tag)

	return plaintext

def tls_signature_context(context_flag, content):
	if context_flag == CLIENT_FLAG:
		context = "TLS 1.3, client CertificateVerify".encode()
	elif context_flag == SERVER_FLAG:
		context = "TLS 1.3, server CertificateVerify".encode()

	repeated_octed = bytes(b'\x20') * 64
	seperator = bytes(b'\x00')
	message = repeated_octed + context + seperator + content

	return message

def tls_signature(signature_algorithm, msg, context_flag):
	tls_msg = tls_signature_context(context_flag, msg)

	if signature_algorithm in [RSA_PKCS1_SHA256, RSA_PKCS1_SHA384]:
		h = SHA256.new(tls_msg) if signature_algorithm == RSA_PKCS1_SHA256 else SHA384.new(tls_msg)
		signer = pkcs1_15.new(RSA2048_KEY)
	elif signature_algorithm == ECDSA_SECP384R1_SHA384:
		h = SHA384.new(tls_msg)
		signer = DSS.new(SECP384R1_KEY, 'fips-186-3')

	signature = signer.sign(h)
	return signature

def tls_verify_signature(signature_algorithm, message, context_flag, signature, public_key):
	tls_msg = tls_signature_context(context_flag, message)

	if signature_algorithm in [RSA_PKCS1_SHA256, RSA_PKCS1_SHA384]:
		h = SHA256.new(tls_msg) if signature_algorithm == RSA_PKCS1_SHA256 else SHA384.new(tls_msg)
		verifier = pkcs1_15.new(public_key)
	elif signature_algorithm == ECDSA_SECP384R1_SHA384:
		h = SHA384.new(tls_msg)
		verifier = DSS.new(public_key, 'fips-186-3')

	verifier.verify(h, signature)