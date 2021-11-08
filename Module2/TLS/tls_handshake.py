#!/usr/bin/env python

'''
tls_handshake.py:
Implementation of the TLS 1.3 Handshake Protocol
'''

from typing import Dict, List, Tuple
from Cryptodome.Random import get_random_bytes
import tls_crypto
import tls_constants
from tls_error import (NoCommonCiphersuiteError, NoCommonGroupError, NoCommonSignatureError, NoCommonVersionError, StateConfusionError, InvalidMessageStructureError, VerificationFailure, WrongLengthError,
                       WrongRoleError)
import tls_extensions


class Handshake:
    "This is the class for the handshake protocol"

    def __init__(self, csuites: List[int], extensions: Dict[int, List[int]], role: int):
        self.csuites = csuites
        self.extensions = extensions
        self.state = tls_constants.INIT_STATE
        self.role = role
        self.csuite = None

        self.master_secret = None
        self.client_hs_traffic_secret = None
        self.server_hs_traffic_secret = None
        self.client_ap_traffic_secret = None
        self.server_ap_traffic_secret = None

        self.ec_sec_keys = {}
        self.ec_sec_key = None
        self.ec_pub_key = None
        self.pub_key = None

        self.server_cert = None
        self.server_cert_string = None

        self.neg_group = None
        self.neg_version = None
        self.signature = None
        self.sid = None
        self.chelo = None
        self.remote_csuites = None
        self.num_remote_csuites = None
        self.remote_extensions = None
        # server selected identity in client
        self.selected_identity = None

        self.transcript = "".encode()
        self.get_random_bytes = get_random_bytes

    def tls_13_compute_server_hs_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE A HANDSHAKE KEY
        if self.server_hs_traffic_secret == None:
            raise StateConfusionError()
        handshake_key, handshake_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.server_hs_traffic_secret)
        return handshake_key, handshake_iv, self.csuite

    def tls_13_compute_client_hs_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE A HANDSHAKE KEY
        if self.client_hs_traffic_secret == None:
            raise StateConfusionError()
        handshake_key, handshake_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.client_hs_traffic_secret)
        return handshake_key, handshake_iv, self.csuite

    def tls_13_compute_server_ap_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE An APPLICATION KEY
        if self.server_ap_traffic_secret == None:
            raise StateConfusionError()
        application_key, application_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.server_ap_traffic_secret)
        return application_key, application_iv, self.csuite

    def tls_13_compute_client_ap_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE AN APPLICATION KEY
        if self.client_ap_traffic_secret == None:
            raise StateConfusionError()
        application_key, application_iv = tls_crypto.tls_derive_key_iv(
            self.csuite, self.client_ap_traffic_secret)
        return application_key, application_iv, self.csuite

    def attach_handshake_header(self, msg_type: int, msg: bytes) -> bytes:
        len_msg = len(msg).to_bytes(3, 'big')
        hs_msg_type = msg_type.to_bytes(1, 'big')
        return hs_msg_type + len_msg + msg

    def process_handshake_header(self, msg_type: int, msg: bytes) -> bytes:
        curr_pos = 0
        curr_msg_type = msg[curr_pos]
        if curr_msg_type != msg_type:
            raise InvalidMessageStructureError()
        curr_pos = curr_pos + tls_constants.MSG_TYPE_LEN
        msg_len = int.from_bytes(
            msg[curr_pos:curr_pos + tls_constants.MSG_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.MSG_LEN_LEN
        ptxt_msg = msg[curr_pos:]
        if msg_len != len(ptxt_msg):
            raise InvalidMessageStructureError()
        return ptxt_msg

    def encode_list(self, size: int, list: List[int]) -> bytes:
        res = b''
        for el in list:
            res += el.to_bytes(size, byteorder='big')
        return res

    def _tls_13_client_hello_chelo_ext(self) -> bytes:
        # struct {
        # ProtocolVersion legacy_version = 0x0303; /* TLS v1.2 */
        protocol_version = 0x0303.to_bytes(2, byteorder='big')
        # Random random;
        random = self.get_random_bytes(tls_constants.RANDOM_LEN)
        # opaque legacy_session_id<0..32>;
        legacy_session_id = self.get_random_bytes(tls_constants.RANDOM_LEN) # not sure if TRNG is necessary, but why not use it.
        self.client_sid = legacy_session_id # to be able to check it later
        legsess_len = tls_constants.RANDOM_LEN.to_bytes(1, byteorder='big')
        # CipherSuite cipher_suites<2..2^16-2>;
        csuite = self.encode_list(2, self.csuites)
        #assert len(csuite) % 2 == 0 # as ChihperSuite is 2B
        csuite_len = len(csuite).to_bytes(tls_constants.CSUITE_LEN_LEN, byteorder='big')
        # opaque legacy_compression_methods<1..2^8-1>;
        legacy_compression_meth = 0x0.to_bytes(1, byteorder='big')
        comp_len = len(legacy_compression_meth).to_bytes(tls_constants.COMP_LEN_LEN, byteorder='big')
        # Extension extensions<8..2^16-1>;
            # struct {
            # ExtensionType extension_type;
            # opaque extension_data<0..2^16-1>;
            # } Extension;
        # 1. Supported Version
        supp_vers_ext = tls_extensions.prep_support_vers_ext(self.extensions)
        # 2. Supported Group
        supp_groups_ext = tls_extensions.prep_support_groups_ext(self.extensions)
        # 3. Keyshare
        keyshare_ext, self.ec_sec_keys = tls_extensions.prep_keyshare_ext(self.extensions)
        # 4. Signature Algorithm
        supp_sigs_ext = tls_extensions.prep_signature_ext(self.extensions)

        extensions = supp_vers_ext + supp_groups_ext + keyshare_ext + supp_sigs_ext
        chelo = protocol_version + random + legsess_len + legacy_session_id + csuite_len \
            + csuite + comp_len + legacy_compression_meth
        return chelo, extensions

    def _tls_13_client_hello_finish_off(self, client_hello):
        self.chelo = client_hello
        chelo_msg = self.attach_handshake_header(tls_constants.CHELO_TYPE, client_hello)
        self.transcript += chelo_msg
        return chelo_msg

    def tls_13_client_hello(self) -> bytes:
        upto, extensions = self._tls_13_client_hello_chelo_ext()
        ext_len = len(extensions).to_bytes(tls_constants.EXT_LEN_LEN, byteorder='big')
        # } ClientHello;
        client_hello = upto + ext_len + extensions
        return self._tls_13_client_hello_finish_off(client_hello)

    def tls_13_process_client_hello(self, chelo_msg: bytes):
        # DECONSTRUCT OUR CLIENTHELLO MESSAGE
        chelo = self.process_handshake_header(
            tls_constants.CHELO_TYPE, chelo_msg)
        curr_pos = 0
        chelo_vers = chelo[curr_pos:curr_pos + tls_constants.MSG_VERS_LEN]
        curr_pos = curr_pos + tls_constants.MSG_VERS_LEN
        chelo_rand = chelo[curr_pos:curr_pos + tls_constants.RANDOM_LEN]
        curr_pos = curr_pos + tls_constants.RANDOM_LEN
        chelo_sess_id_len = chelo[curr_pos]
        curr_pos = curr_pos + tls_constants.SID_LEN_LEN
        self.sid = chelo[curr_pos:curr_pos+chelo_sess_id_len]
        curr_pos = curr_pos+chelo_sess_id_len
        csuites_len = int.from_bytes(
            chelo[curr_pos:curr_pos+tls_constants.CSUITE_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.CSUITE_LEN_LEN
        self.remote_csuites = chelo[curr_pos:curr_pos+csuites_len]
        curr_pos = curr_pos + csuites_len
        self.num_remote_csuites = csuites_len//tls_constants.CSUITE_LEN
        comp_len = int.from_bytes(
            chelo[curr_pos:curr_pos+tls_constants.COMP_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.COMP_LEN_LEN
        legacy_comp = chelo[curr_pos]
        if legacy_comp != 0x00:
            raise InvalidMessageStructureError()
        curr_pos = curr_pos + comp_len
        exts_len = int.from_bytes(
            chelo[curr_pos:curr_pos+tls_constants.EXT_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.EXT_LEN_LEN
        self.remote_extensions = chelo[curr_pos:curr_pos+exts_len]
        self.transcript = self.transcript + chelo_msg

    def _tls_13_server_get_remote_extensions_switch(self, ext_type, ext_bytes):
        if ext_type == tls_constants.SUPPORT_VERS_TYPE:
            return 'supported versions', ext_bytes
        if ext_type == tls_constants.SUPPORT_GROUPS_TYPE:
            return 'supported groups', ext_bytes
        if ext_type == tls_constants.KEY_SHARE_TYPE:
            return 'key share', ext_bytes
        if ext_type == tls_constants.SIG_ALGS_TYPE:
            return 'sig algs', ext_bytes

    def tls_13_server_get_remote_extensions(self) -> Dict[str, bytes]:
        curr_ext_pos = 0
        remote_extensions = {}
        while curr_ext_pos < len(self.remote_extensions):
            ext_type = int.from_bytes(
                self.remote_extensions[curr_ext_pos:curr_ext_pos+2], 'big')
            curr_ext_pos = curr_ext_pos + 2
            ext_len = int.from_bytes(
                self.remote_extensions[curr_ext_pos:curr_ext_pos+2], 'big')
            curr_ext_pos = curr_ext_pos + 2
            ext_bytes = self.remote_extensions[curr_ext_pos:curr_ext_pos+ext_len]
            curr_ext_pos = curr_ext_pos + ext_len
            # Move it out to be extended for the psk handshake
            key, value = self._tls_13_server_get_remote_extensions_switch(ext_type, ext_bytes)
            if key is not None:
                remote_extensions[key] = value
        return remote_extensions

    def _tls_13_server_select_parameters_supported(self, remote_extensions: Dict[str, bytes]):
        self.neg_version = tls_extensions.negotiate_support_vers_ext(
            self.extensions, remote_extensions['supported versions'])
        self.neg_group = tls_extensions.negotiate_support_group_ext(
            self.extensions, remote_extensions['supported groups'])

    def _tls_13_server_select_parameters_dhe(self, remote_extensions: Dict[str, bytes]):
        (self.pub_key, self.neg_group, self.ec_pub_key,
         self.ec_sec_key) = tls_extensions.negotiate_keyshare(
            self.extensions, self.neg_group, remote_extensions['key share'])
    
    def _tls_13_server_select_parameters_sig_csuite(self, remote_extensions: Dict[str, bytes]):
        self.signature = tls_extensions.negotiate_signature_ext(
            self.extensions, remote_extensions['sig algs'])
        self.csuite = tls_extensions.negotiate_support_csuite(
            self.csuites, self.num_remote_csuites, self.remote_csuites)
    
    def tls_13_server_select_parameters(self, remote_extensions: Dict[str, bytes]):
        self._tls_13_server_select_parameters_supported(remote_extensions)

        self._tls_13_server_select_parameters_dhe(remote_extensions)

        self._tls_13_server_select_parameters_sig_csuite(remote_extensions)

    def _tls_13_prep_server_hello_create_extensions(self):
        # WE ATTACH ALL OUR EXTENSIONS
        neg_vers_ext = tls_extensions.finish_support_vers_ext(self.neg_version)
        neg_group_ext = tls_extensions.finish_support_group_ext(self.neg_group)
        supported_keyshare = tls_extensions.finish_keyshare_ext(self.pub_key, self.neg_group)
        extensions = neg_vers_ext + neg_group_ext + supported_keyshare

        return extensions

    def _tls_13_prep_server_hello_derive_secrets(self):
        early_secret = tls_crypto.tls_extract_secret(self.csuite, None, None)
        derived_early_secret = tls_crypto.tls_derive_secret(
            self.csuite, early_secret, "derived".encode(), "".encode())
        ecdh_secret_point = tls_crypto.ec_dh(self.ec_sec_key, self.ec_pub_key)
        ecdh_secret = tls_crypto.point_to_secret(
            ecdh_secret_point, self.neg_group)
        handshake_secret = tls_crypto.tls_extract_secret(
            self.csuite, ecdh_secret, derived_early_secret)
        self.server_hs_traffic_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "s hs traffic".encode(), self.transcript)
        self.client_hs_traffic_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "c hs traffic".encode(), self.transcript)
        derived_hs_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "derived".encode(), "".encode())
        self.master_secret = tls_crypto.tls_extract_secret(
            self.csuite, None, derived_hs_secret)

    def tls_13_prep_server_hello(self) -> bytes:
        # ALL OF THE LEGACY TLS SERVERHELLO INFORMATION
        # Must be set like this for compatability reasons
        legacy_vers = tls_constants.LEGACY_VERSION.to_bytes(2, 'big')
        # Must be set like this for compatability reasons
        random = get_random_bytes(32)
        legacy_sess_id = self.sid  # Must be set like this for compatability reasons
        legacy_sess_id_len = len(self.sid).to_bytes(1, 'big')
        legacy_compression = (0x00).to_bytes(1, 'big')
        csuite_bytes = self.csuite.to_bytes(2, 'big')
        extensions = self._tls_13_prep_server_hello_create_extensions()
        exten_len = len(extensions).to_bytes(2, 'big')
        msg = legacy_vers + random + legacy_sess_id_len + legacy_sess_id + \
            csuite_bytes + legacy_compression + exten_len + extensions
        shelo_msg = self.attach_handshake_header(tls_constants.SHELO_TYPE, msg)
        self.transcript += shelo_msg
        
        self._tls_13_prep_server_hello_derive_secrets()

        return shelo_msg

    def _tls_13_process_server_hello_to_extenstions(self, shelo_msg):
        # for parsing this see thread: https://moodle-app2.let.ethz.ch/mod/forum/discuss.php?d=87748
        self.transcript += shelo_msg
        shelo = self.process_handshake_header(tls_constants.SHELO_TYPE, shelo_msg)
        # should be: legacy_vers + random + legacy_sess_id_len + legacy_sess_id + \
        #    csuite_bytes + legacy_compression + exten_len + extensions
        curr_pos = 0
        # ProtocolVersion
        legacy_vers = shelo[curr_pos:curr_pos + tls_constants.PROTOCOL_VERSION_LEN]
        curr_pos = curr_pos + tls_constants.PROTOCOL_VERSION_LEN
        if int.from_bytes(legacy_vers, 'big') != 0x0303 and int.from_bytes(legacy_vers, 'big') != 0x0301: # looks good
            raise NoCommonVersionError()
        # Random
        curr_pos = curr_pos + tls_constants.RANDOM_LEN
        # legacy_session_id_echo
        sess_id_len = int.from_bytes(shelo[curr_pos:curr_pos+tls_constants.SID_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.SID_LEN_LEN
        if sess_id_len != 32:
            raise InvalidMessageStructureError()
        session_id = shelo[curr_pos:curr_pos+sess_id_len]
        curr_pos = curr_pos+sess_id_len
        # CSuite
        self.csuite = int.from_bytes(shelo[curr_pos:curr_pos+tls_constants.CSUITE_LEN], 'big')
        if self.csuite not in tls_constants.SERVER_SUPPORTED_CIPHERSUITES:
            raise InvalidMessageStructureError()
        curr_pos = curr_pos + tls_constants.CSUITE_LEN
        # print('0x%02x'%self.csuite) # returns nice 0x1301 --> TLS_AES_128_GCM_SHA256
        # legacy_compression_method
        comp_method = int.from_bytes(shelo[curr_pos:curr_pos+1], 'big')
        curr_pos = curr_pos + 1 # server legacy compression is a constant 0
        if comp_method != 0x00:
            print(f"In tls_13_process_server_hello the message has non-zero legacy_compression_method!")
            raise InvalidMessageStructureError()
        # extensions
        exts_len = int.from_bytes(shelo[curr_pos:curr_pos+tls_constants.EXT_LEN_LEN], 'big')
        curr_pos = curr_pos + tls_constants.EXT_LEN_LEN
        remote_extensions = shelo[curr_pos:]
        if len(remote_extensions) != exts_len:
            print(f"In tls_13_process_server_hello the message has wrong length for the extensions!")
            raise InvalidMessageStructureError()
        return remote_extensions

    def _tls_13_process_server_hello_process_extensions(self, ext_type, ext_bytes):
        # Old stuff without PSK or 0-RTT
        if (ext_type == tls_constants.SUPPORT_VERS_TYPE):
            if len(ext_bytes) != 2:
                raise InvalidMessageStructureError()
            self.neg_version = int.from_bytes(ext_bytes, 'big')
        if (ext_type == tls_constants.SUPPORT_GROUPS_TYPE):
            if len(ext_bytes) != 2:
                raise InvalidMessageStructureError()
            self.neg_group = int.from_bytes(ext_bytes[1:], 'big')
        if (ext_type == tls_constants.SIG_ALGS_TYPE):
            # Should not be returned at all!
            raise InvalidMessageStructureError()
        if (ext_type == tls_constants.KEY_SHARE_TYPE):
            named_group = int.from_bytes(ext_bytes[0:2], 'big')
            #print('named_group: 0x%04x'%named_group) # returns 0x0017
            key_exchange_len = int.from_bytes(ext_bytes[2:4], 'big')
            key_exchange_field = ext_bytes[4:] # 4 because 2B size
            if len(key_exchange_field) != key_exchange_len:
                raise InvalidMessageStructureError()
            # SECP256R1_VALUE, SECP384R1_VALUE, SECP521R1_VALUE
            #  For secp256r1, secp384r1, and secp521r1, the contents are the serialized value of the following struct:
            #  struct {
            #  uint8 legacy_form = 4;
            legacy_form = int.from_bytes(key_exchange_field[0:1], 'big')
            if legacy_form != 0x04:
                raise InvalidMessageStructureError()
            #  opaque X[coordinate_length];
            #  opaque Y[coordinate_length];
            #  } UncompressedPointRepresentation;
            # Peers MUST validate each other’s public key Y by ensuring that 1 < Y < p-1. --> done by tinyEC
            self.ec_pub_key = tls_crypto.convert_x_y_bytes_ec_pub(key_exchange_field[1:], named_group)

    def _tls_13_process_server_hello_secret_derivation(self):
        # Compute the Diffie-Hellman secret value
        if self.neg_group not in self.ec_sec_keys.keys():
            raise NoCommonGroupError()
        ec_sec_key = self.ec_sec_keys[self.neg_group]
        ec_secret_point = tls_crypto.ec_dh(ec_sec_key, self.ec_pub_key)
        ecdh_secret = tls_crypto.point_to_secret(ec_secret_point, self.neg_group)
        # Derive the secrets
        early_secret = tls_crypto.tls_extract_secret(self.csuite, None, None)
        self.early_secret = early_secret
        # +-----> Derive-Secret(., "ext binder" | "res binder", "") = binder_key
        # For the computation of the  binder_key, the label is "ext binder" for external PSKs (those
        # provisioned outside of TLS) and "res binder" for resumption PSKs
        # (those provisioned as the resumption master secret of a previous handshake).
        #binder_key = tls_crypto.tls_derive_secret(
        #    self.csuite, early_secret, "ext binder".encode(), "".encode())
        # +-----> Derive-Secret(., "c e traffic", ClientHello) = client_early_traffic_secret
        #client_early_traffic_secret = tls_crypto.tls_derive_secret(
        #    self.csuite, early_secret, "c e traffic".encode(), self.chelo)
        # +-----> Derive-Secret(., "e exp master", ClientHello) = early_exporter_master_secret
        #early_exporter_master_secret = tls_crypto.tls_derive_secret(
        #    self.csuite, early_secret, "e exp master".encode(), self.chelo)
        # Derive-Secret(., "derived", "")
        derived_early_secret = tls_crypto.tls_derive_secret(
            self.csuite, early_secret, "derived".encode(), "".encode())
        
        # (EC)DHE -> HKDF-Extract = Handshake Secret; completely the same as server
        #transcript_hash = tls_crypto.tls_transcript_hash(
        #    self.csuite, self.transcript)
        handshake_secret = tls_crypto.tls_extract_secret(
            self.csuite, ecdh_secret, derived_early_secret)
        self.handshake_secret = handshake_secret
        self.server_hs_traffic_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "s hs traffic".encode(), self.transcript)
        self.client_hs_traffic_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "c hs traffic".encode(), self.transcript)
        derived_hs_secret = tls_crypto.tls_derive_secret(
            self.csuite, handshake_secret, "derived".encode(), "".encode())
        
        self.master_secret = tls_crypto.tls_extract_secret(
            self.csuite, None, derived_hs_secret)

    def tls_13_process_server_hello(self, shelo_msg: bytes):
        remote_extensions = self._tls_13_process_server_hello_to_extenstions(shelo_msg)

        curr_ext_pos = 0
        while (curr_ext_pos < len(remote_extensions)):
            # ExtensionType
            ext_type = int.from_bytes(remote_extensions[curr_ext_pos:curr_ext_pos+tls_constants.EXT_LEN_LEN], 'big')
            curr_ext_pos += tls_constants.EXT_LEN_LEN
            # extension_data_len
            ext_len = int.from_bytes(remote_extensions[curr_ext_pos:curr_ext_pos+tls_constants.EXT_LEN_LEN], 'big')
            curr_ext_pos += tls_constants.EXT_LEN_LEN
            # get actual data
            ext_bytes = remote_extensions[curr_ext_pos:curr_ext_pos+ext_len]
            curr_ext_pos += ext_len
            # Actually handle the extension
            self._tls_13_process_server_hello_process_extensions(ext_type, ext_bytes)
        if curr_ext_pos != len(remote_extensions):
            # as we should have perfectly used up all bytes
            print(f"In tls_13_process_server_hello the message has wrong format in the extensions!")
            raise InvalidMessageStructureError()
            
        # Compute the Diffie-Hellman secret value
        self._tls_13_process_server_hello_secret_derivation()
        
    def tls_13_server_enc_ext(self):
        msg = 0x0000.to_bytes(2, 'big')
        enc_ext_msg = self.attach_handshake_header(
            tls_constants.ENEXT_TYPE, msg)
        self.transcript = self.transcript + enc_ext_msg
        return enc_ext_msg

    def tls_13_process_enc_ext(self, enc_ext_msg: bytes):
        enc_ext = self.process_handshake_header(
            tls_constants.ENEXT_TYPE, enc_ext_msg)
        if enc_ext != 0x0000.to_bytes(2, 'big'):
            raise InvalidMessageStructureError
        self.transcript = self.transcript + enc_ext_msg

    def tls_13_server_cert(self):
        certificate = tls_constants.SERVER_SUPPORTED_CERTIFICATES[self.signature]
        certificate_bytes = certificate.encode()
        cert_extensions = (0x0000).to_bytes(2, 'big')
        cert_len = (len(certificate_bytes) +
                    len(cert_extensions)).to_bytes(3, 'big')
        cert_chain_len = (len(certificate_bytes) +
                          len(cert_extensions) + len(cert_len)).to_bytes(3, 'big')
        cert_context_len = (0x00).to_bytes(1, 'big')
        msg = cert_context_len + cert_chain_len + \
            cert_len + certificate_bytes + cert_extensions
        cert_msg = self.attach_handshake_header(tls_constants.CERT_TYPE, msg)
        self.transcript = self.transcript + cert_msg
        return cert_msg

    def tls_13_process_server_cert(self, cert_msg: bytes):
        cert = self.process_handshake_header(tls_constants.CERT_TYPE, cert_msg)
        msg_len = len(cert)
        curr_pos = 0
        cert_context_len = cert[curr_pos]
        curr_pos = curr_pos + 1
        if cert_context_len != 0:
            cert_context = cert_msg[curr_pos:curr_pos + cert_context_len]
        curr_pos = curr_pos + cert_context_len
        while curr_pos < msg_len:
            cert_chain_len = int.from_bytes(
                cert[curr_pos: curr_pos + 3], 'big')
            curr_pos = curr_pos + 3
            cert_chain = cert[curr_pos:curr_pos+cert_chain_len]
            curr_chain_pos = 0
            while curr_chain_pos < cert_chain_len:
                cert_len = int.from_bytes(
                    cert_chain[curr_chain_pos: curr_chain_pos + 3], 'big')
                curr_chain_pos = curr_chain_pos + 3
                self.server_cert = cert_chain[curr_chain_pos:curr_chain_pos + cert_len - 2]
                self.server_cert_string = self.server_cert.decode('utf-8')
                # SUBTRACT TWO FOR THE EXTENSIONS, WHICH WILL ALWAYS BE EMPTY
                curr_chain_pos = curr_chain_pos + cert_len
            curr_pos = curr_pos + cert_chain_len
        self.transcript = self.transcript + cert_msg

    def tls_13_server_cert_verify(self) -> bytes:
        transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
        signature = tls_crypto.tls_signature(self.signature, transcript_hash, tls_constants.SERVER_FLAG)
        len_sig_bytes = len(signature).to_bytes(2, 'big')
        sig_type_bytes = self.signature.to_bytes(2, 'big')
        msg = sig_type_bytes + len_sig_bytes + signature
        cert_verify_msg = self.attach_handshake_header(
            tls_constants.CVFY_TYPE, msg)
        self.transcript = self.transcript + cert_verify_msg
        return cert_verify_msg

    def tls_13_process_server_cert_verify(self, verify_msg: bytes):
        verify = self.process_handshake_header(tls_constants.CVFY_TYPE, verify_msg)
        curr_pos = 0
        # SignatureScheme alg
        signature_scheme_alg = int.from_bytes(verify[curr_pos:curr_pos+2], 'big')
        curr_pos += 2
        # signature
        signature_len = int.from_bytes(verify[curr_pos:curr_pos+2], 'big')
        curr_pos += 2
        signature_bytes = verify[curr_pos:curr_pos+signature_len]
        curr_pos += signature_len
        if len(verify) != curr_pos:
            raise InvalidMessageStructureError()
        
        # Get the server pbublic key
        server_pub_key = None
        if signature_scheme_alg == tls_constants.RSA_PKCS1_SHA256 or signature_scheme_alg == tls_constants.RSA_PKCS1_SHA384:
            server_pub_key = tls_crypto.get_rsa_pk_from_cert(self.server_cert_string)
        if signature_scheme_alg == tls_constants.ECDSA_SECP384R1_SHA384:
            server_pub_key = tls_crypto.get_ecdsa_pk_from_cert(self.server_cert_string)
        if server_pub_key is None:
            raise NoCommonSignatureError()

        # Do the signature verify
        transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
        # Following should throw an error by itself
        tls_crypto.tls_verify_signature(signature_scheme_alg, transcript_hash, tls_constants.SERVER_FLAG, signature_bytes, server_pub_key)
        self.transcript += verify_msg

    def tls_13_finished(self) -> bytes:
        transcript_hash = tls_crypto.tls_transcript_hash(
            self.csuite, self.transcript)
        finished_key = tls_crypto.tls_finished_key_derive(
            self.csuite, self.server_hs_traffic_secret)
        tag = tls_crypto.tls_finished_mac(
            self.csuite, finished_key, transcript_hash)
        fin_msg = self.attach_handshake_header(tls_constants.FINI_TYPE, tag)
        self.transcript = self.transcript + fin_msg
        if self.role == tls_constants.SERVER_FLAG:
            transcript_hash = tls_crypto.tls_transcript_hash(
                self.csuite, self.transcript)
            self.server_ap_traffic_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "s ap traffic".encode(), transcript_hash)
            self.client_ap_traffic_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "c ap traffic".encode(), transcript_hash)
        
        return fin_msg

    def tls_13_process_finished(self, fin_msg: bytes):
        finished = self.process_handshake_header(tls_constants.FINI_TYPE, fin_msg)
        if self.csuite == tls_constants.TLS_AES_128_GCM_SHA256:
            mac_len = tls_constants.SHA_256_LEN
        if self.csuite == tls_constants.TLS_AES_256_GCM_SHA384:
            mac_len = tls_constants.SHA_384_LEN
        if self.csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256:
            mac_len = tls_constants.SHA_256_LEN
        if len(finished) != mac_len:
            raise WrongLengthError()
        finished_key = tls_crypto.hkdf_expand_label(self.csuite, self.server_hs_traffic_secret, b"finished", b"", mac_len)
        #tls_crypto.tls_finished_key_derive(self.csuite, ) # the server hs might be wrong
        transcript = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
        tls_crypto.tls_finished_mac_verify(self.csuite, finished_key, transcript, finished)
        self.transcript += fin_msg
        if self.role == tls_constants.CLIENT_FLAG:
            transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
            self.server_ap_traffic_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "s ap traffic".encode(), transcript_hash)
            self.client_ap_traffic_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "c ap traffic".encode(), transcript_hash)
        