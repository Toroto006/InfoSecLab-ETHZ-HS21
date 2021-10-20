#!/usr/bin/env python

'''
tls_psk_handshake.py:
A series of functions implementing aspects of TLS 1.3 PSK functionality
'''

import pickle
from io import open
import time
from typing import Dict, List, Tuple, Union
from Cryptodome.Cipher import AES, ChaCha20_Poly1305
from Cryptodome.Hash import HMAC, SHA256, SHA384
from Cryptodome.Random import get_random_bytes
import tls_crypto
import tls_constants
from tls_error import *
import tls_extensions
from tls_handshake import Handshake

generate_client_test = False
generate_server_test = False
generate_server_random_test = False


def timer() -> int:
    return int(time.time()*1000)


class PSKHandshake(Handshake):
    "This is the class for aspects of the handshake protocol"

    __rand_id = 0

    def __init__(self, csuites: List[int], extensions: Dict[int, List[int]], role: int,
                 psks: List[Dict[str, Union[bytes, int]]] = None, psk_modes: List[int] = None,
                 server_static_enc_key: bytes = None, early_data: bytes = None):
        super().__init__(csuites, extensions, role)
        self.psks = psks
        self.psk = None
        self.psk_modes = psk_modes
        self.server_static_enc_key = server_static_enc_key
        self.early_data = early_data
        self.client_early_traffic_secret = None
        self.accept_early_data = False
        self.selected_identity = None
        self.resumption_master_secret = None
        self.max_early_data = None
        self.offered_psks = None
        self.use_keyshare = None
        self.client_early_data = None
        self.get_time = timer
        self.get_random_bytes = get_random_bytes

    def tls_13_server_new_session_ticket(self) -> bytes:
        # struct {
        something = int(0).to_bytes(4, 'big')
        # uint32 ticket_lifetime;
        lifetime = int(604800).to_bytes(4, 'big')
        # uint32 ticket_age_add;
        age_add = self.get_random_bytes(4)
        # opaque ticket_nonce<0..255>;
        nonce = self.get_random_bytes(8)
        nonce_len = len(nonce).to_bytes(1, 'big')
        # opaque ticket<1..2^16-1>;
        # chosen_cipher CHACHA20_POLY1305_SHA256
        # k = self.server_static_enc_key
        # N = ticket_nonce
        # ad = ""
        psk = tls_crypto.hkdf_expand_label(self.csuite, self.resumption_master_secret, b"resumption", nonce, tls_constants.SHA_256_LEN)
        # ptxt = PSK ticket_add_age ticket_lifetime self.csuite
        plaintext = psk + age_add + lifetime + self.csuite.to_bytes(2, 'big') # csuite conversion correct?
        cipher = ChaCha20_Poly1305.new(key=self.server_static_enc_key, nonce=nonce)
        # cipher.update(ad) # no update as empty?
        ctxt, mac_tag = cipher.encrypt_and_digest(plaintext)
        ticket = nonce + ctxt + mac_tag
        ticket_len = len(ticket).to_bytes(2, 'big')
        # Extension extensions<0..2^16-2>;
            # struct {
            # select (Handshake.msg_type) {
            # case new_session_ticket: uint32 max_early_data_size;
            # case client_hello: Empty;
            # case encrypted_extensions: Empty;
            # };} EarlyDataIndication;
        extensions_data = int(2**12).to_bytes(4, 'big')
        extension_type = tls_constants.EARLY_DATA_TYPE.to_bytes(2, 'big')
        extensions = extension_type + len(extensions_data).to_bytes(2, 'big') + extensions_data
        extensions_len = len(extensions).to_bytes(2, 'big')
        # } NewSessionTicket;
        new_session_ticket = lifetime + age_add + nonce_len + nonce + ticket_len + ticket + extensions_len + extensions
        handshake = self.attach_handshake_header(tls_constants.NEWST_TYPE, new_session_ticket)
        return handshake

    def tls_13_client_parse_new_session_ticket(self, nst_msg: bytes) -> Dict[str, Union[bytes, int]]:
        # https://moodle-app2.let.ethz.ch/mod/forum/discuss.php?d=87942 for issues with the binder key creation
        raise NotImplementedError()

    def tls_13_client_prep_psk_mode_extension(self) -> bytes:
        raise NotImplementedError()

    def tls_13_client_add_psk_extension(self, chelo: bytes, extensions: bytes) -> Tuple[bytes, List[Dict[str, Union[bytes, int]]]]:
        # does not include length: https://moodle-app2.let.ethz.ch/mod/forum/discuss.php?d=87711
        raise NotImplementedError()

    def tls_13_server_parse_psk_extension(self, psk_extension: bytes) -> Tuple[bytes, int]:
        raise NotImplementedError()

    def tls_13_client_hello(self) -> bytes:
        raise NotImplementedError()

    def tls_13_compute_client_early_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE A HANDSHAKE KEY
        if self.client_early_traffic_secret is None:
            raise StateConfusionError()
        early_data_key, early_data_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.client_early_traffic_secret)
        return early_data_key, early_data_iv, self.csuite

    def tls_13_eoed(self) -> bytes:
        return self.attach_handshake_header(tls_constants.EOED_TYPE, b'')

    def tls_13_finished(self) -> bytes:
        raise NotImplementedError()

    def tls_13_process_finished(self, fin_msg: bytes):
        raise NotImplementedError()

    def tls_13_early_data_ext(self, data: bytes = b'') -> bytes:
        raise NotImplementedError()
        
    def tls_13_server_enc_ext(self) -> bytes:
        raise NotImplementedError()
        
    def tls_13_process_enc_ext(self, enc_ext_msg: bytes):
        raise NotImplementedError()
        
    def tls_13_server_get_remote_extensions(self) -> Dict[str, bytes]:
        raise NotImplementedError()
        
    def tls_13_server_parse_psk_mode_ext(self, modes_bytes: bytes) -> bytes:
        modes_len = modes_bytes[0]
        modes = modes_bytes[1:modes_len+1]
        return modes

    def tls_13_server_select_parameters(self, remote_extensions: Dict[str, bytes]):
        """This method sets the following fields to indicate the selected parameters:
            self.use_keyshare
            self.client_early_data
            self.neg_version
            self.csuite
            self.psk
            self.selected_identity
            self.use_keyshare
            self.client_early_data
            self.accept_early_data
            self.neg_group
            self.pub_key
            self.ec_pub_key,
            self.ec_sec_key
            self.signature
        """
        raise NotImplementedError()

    def tls_13_prep_server_hello(self) -> bytes:
        """ Creates the Server Hello message, updates the transcript, and sets the following fields:
            self.client_erly_secret
            self.server_hs_traffic_secret
            self.client_hs_traffic_secret
            self.master_secret
        """
        raise NotImplementedError()

    def tls_13_process_server_hello(self, shelo_msg: bytes):
        raise NotImplementedError()