#!/usr/bin/env python

'''
tls_psk_handshake.py:
A series of functions implementing aspects of TLS 1.3 PSK functionality
'''

import pickle
from io import open
import time
from typing import ContextManager, Dict, List, Tuple, Union
from Cryptodome.Cipher import AES, ChaCha20_Poly1305
from Cryptodome.Hash import HMAC, SHA256, SHA384
from Cryptodome.Random import get_random_bytes
import tls_crypto
import tls_constants
from tls_error import *
import tls_extensions
import itertools
from tls_handshake import Handshake

generate_client_test = False
generate_server_test = False
generate_server_random_test = False


def timer() -> int:
    return int(time.time()*1000)

def print_dict(dict, hexes):
    for k, v in dict.items():
        val = v
        if k in hexes:
            val = v.hex()
        print(f"{k}: {val}")

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
        self.use_keyshare = True
        self.client_early_data = None
        self.get_time = timer
        self.get_random_bytes = get_random_bytes
        self.eoed_msg = None

    def tls_13_server_new_session_ticket(self) -> bytes:
        # struct {
        # uint32 ticket_lifetime;
        lifetime = int(604800).to_bytes(4, 'big')
        # uint32 ticket_age_add;
        age_add = self.get_random_bytes(4)
        # opaque ticket_nonce<0..255>;
        ticket_nonce = self.get_random_bytes(8)
        nonce_len = len(ticket_nonce).to_bytes(1, 'big')
        # opaque ticket<1..2^16-1>;
            # chosen_cipher CHACHA20_POLY1305_SHA256
            # k = self.server_static_enc_key
            # N = ticket_nonce
            # ad = ""
        if (self.csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (self.csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
            hash_len = tls_constants.SHA_256_LEN
        if (self.csuite == tls_constants.TLS_AES_256_GCM_SHA384):
            hash_len = tls_constants.SHA_384_LEN
        psk = tls_crypto.hkdf_expand_label(self.csuite, self.resumption_master_secret, b"resumption", ticket_nonce, hash_len)
        # ptxt = PSK ticket_add_age ticket_lifetime self.csuite
        plaintext = psk + age_add + lifetime + self.csuite.to_bytes(2, 'big') # csuite conversion correct?
        cipher = ChaCha20_Poly1305.new(key=self.server_static_enc_key, nonce=ticket_nonce)
        # cipher.update(ad) # no update as empty?
        ctxt, mac_tag = cipher.encrypt_and_digest(plaintext)
        ticket = ticket_nonce + ctxt + mac_tag
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
        new_session_ticket = lifetime + age_add + nonce_len + ticket_nonce + ticket_len + ticket + extensions_len + extensions
        handshake = self.attach_handshake_header(tls_constants.NEWST_TYPE, new_session_ticket)
        return handshake

    def tls_13_client_parse_new_session_ticket(self, nst_msg: bytes) -> Dict[str, Union[bytes, int]]:
        arrival_time = self.get_time()
        # https://moodle-app2.let.ethz.ch/mod/forum/discuss.php?d=87942 for issues with the binder key creation
        nst = self.process_handshake_header(tls_constants.NEWST_TYPE, nst_msg)
        cur_pos = 0
        lifetime = int.from_bytes(nst[cur_pos:cur_pos+4], 'big')
        cur_pos += 4
        age_add = int.from_bytes(nst[cur_pos:cur_pos+4], 'big')
        cur_pos += 4
        nonce_len = int.from_bytes(nst[cur_pos:cur_pos + 1], 'big')
        cur_pos = cur_pos + 1
        if nonce_len != 8: # we know its 8 bytes
            raise InvalidMessageStructureError()
        ticket_nonce = nst[cur_pos:cur_pos+nonce_len]
        cur_pos += nonce_len
        ticket_len = int.from_bytes(nst[cur_pos:cur_pos + 2], 'big')
        cur_pos = cur_pos + 2
        if ticket_len < 1 or ticket_len > 2**16-2: # we know it has to be in 1 to 2**16-2
            raise InvalidMessageStructureError()
        ticket = nst[cur_pos:cur_pos+ticket_len]
        cur_pos += ticket_len
        extensions_len = int.from_bytes(nst[cur_pos:cur_pos + 2], 'big')
        cur_pos = cur_pos + 2
        extensions = nst[cur_pos:cur_pos + extensions_len]
        cur_pos += extensions_len
        if cur_pos != len(nst):
            raise InvalidMessageStructureError()
        # parse the ticket
        #t_cur_pos = 0
        #nonce = ticket[t_cur_pos:t_cur_pos+nonce_len]
        #t_cur_pos += nonce_len
        #if nonce != ticket_nonce: # Ticket nonce is not the same nonce!
        #    raise InvalidMessageStructureError()
        #ctxt = ticket[t_cur_pos:t_cur_pos+42]
        #t_cur_pos += 42 # 42 = 32 sha + 4 + 4 + 2
        #mac_tag = ticket[t_cur_pos:t_cur_pos+tls_constants.MAC_LEN[self.csuite]]
        #t_cur_pos += tls_constants.MAC_LEN[self.csuite]
        #if t_cur_pos != len(ticket):
        #    raise InvalidMessageStructureError()

        if (self.csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (self.csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
            hash_len = tls_constants.SHA_256_LEN
        if (self.csuite == tls_constants.TLS_AES_256_GCM_SHA384):
            hash_len = tls_constants.SHA_384_LEN
        psk = tls_crypto.hkdf_expand_label(self.csuite, self.resumption_master_secret, b"resumption", ticket_nonce, hash_len)
        #print(f"Client psk: {psk.hex()}")
        # extract max data from extension
        ext_type = int.from_bytes(extensions[0:2], 'big')
        max_data = None
        curr_ext_pos = 0
        while curr_ext_pos < len(extensions):
            ext_type = int.from_bytes(extensions[curr_ext_pos:curr_ext_pos+2], 'big')
            curr_ext_pos = curr_ext_pos + 2
            ext_len = int.from_bytes(extensions[curr_ext_pos:curr_ext_pos+2], 'big')
            curr_ext_pos = curr_ext_pos + 2
            ext_bytes = extensions[curr_ext_pos:curr_ext_pos+ext_len]
            if ext_type == tls_constants.EARLY_DATA_TYPE:
                max_data = int.from_bytes(ext_bytes, 'big')
            curr_ext_pos = curr_ext_pos + ext_len
        if max_data is None:
            print("I'm missing the EARLY_DATA_TYPE for the max_data")
            raise InvalidMessageStructureError()
        # Calculate the binder_key = Derive the secrets
        early_secret = tls_crypto.tls_extract_secret(self.csuite, psk, None)
        # +-----> Derive-Secret(., "ext binder" | "res binder", "") = binder_key
        # For the computation of the  binder_key, the label is "ext binder" for external PSKs (those
        # provisioned outside of TLS) and "res binder" for resumption PSKs
        # (those provisioned as the resumption master secret of a previous handshake).
        binder_key = tls_crypto.tls_derive_secret(self.csuite, early_secret, "res binder".encode(), "".encode())
        psk_dict = {
            "PSK": psk,
            "lifetime": lifetime,
            "lifetime_add": age_add,
            "ticket": ticket,
            "max_data": max_data,
            "binder key": binder_key,
            "csuite": self.csuite,
            "arrival": arrival_time
        }
        #print_dict(psk_dict, ['PSK', 'ticket', 'binder key'])
        return psk_dict

    def tls_13_client_prep_psk_mode_extension(self) -> bytes:
        # enum { psk_ke(0), psk_dhe_ke(1), (255) } PskKeyExchangeMode; --> 1B ???
        # struct {
        # PskKeyExchangeMode ke_modes<1..255>;
        # } PskKeyExchangeModes;
        extensions_data = len(self.psk_modes).to_bytes(1, 'big') # < ... > len def
        for mode in self.psk_modes:
            extensions_data += mode.to_bytes(1, 'big') # 255 is 1B each
        # Make it into an extension
        extension_type = tls_constants.PSK_KEX_MODE_TYPE.to_bytes(2, 'big')
        extension = extension_type + len(extensions_data).to_bytes(2, 'big') + extensions_data
        return extension

    def tls_13_client_add_psk_extension(self, chelo: bytes, extensions: bytes) -> Tuple[bytes, List[Dict[str, Union[bytes, int]]]]:
        # does not include length: https://moodle-app2.let.ethz.ch/mod/forum/discuss.php?d=87711
        fct_enter_time = self.get_time()
        # PSK_TYPE == pre_shared_key extension type
        psk_extension_type = tls_constants.PSK_TYPE.to_bytes(2, 'big')
        psks_offered = []
        for psk in self.psks:
            # TODO Following two not in use right now (PSK later but not here)
            # PSK: b"\xa2\xbb\xc1\xc3\xc2\x93&/qe\x16fb\xa4\x8a\x97\xcd'3F\xab\xa8\xa0\x16d\xa6\xb9\x1d\xc2\tz\xfe"
            # max_data: 4096
            identity = psk['ticket']
            if len(identity) >= 2**16-1:
                print(f"An identity was too big: {identity}")
                continue
            ticket_age = fct_enter_time - psk['arrival']
            lifetime = psk['lifetime'] * 1000
            if ticket_age > lifetime:
                #print(f"A ticket was too old: {ticket_age} with max {lifetime}")
                continue
            # If accepted add it to the offers
            psks_offered.append(psk)

        if len(psks_offered) == 0:
            #print("No psks to offer!")
            return psk_extension_type + 0x0.to_bytes(2, 'big'), []
        
        identity_list = []
        binders_size = 0
        # Now that we know which psks to offer, lets create the identities list and calculate the binders size
        for psk in psks_offered:
            identity = len(psk['ticket']).to_bytes(2, 'big') + psk['ticket'] # psk['ticket'] was defined as our identity
            # obfuscated_ticket_age is a representation of the ticket age added to the “lifetime_add” value saved in the PSK dictionary, modulo 2**32
            ticket_age = fct_enter_time - psk['arrival']
            lifetime = psk['lifetime'] * 1000
            obfuscated_ticket_age = (psk['lifetime_add']+ticket_age)%(2**32)
            # struct {
            # opaque identity<1..2^16-1>;
            # uint32 obfuscated_ticket_age;
            # } PskIdentity;
            psk_identity = identity + obfuscated_ticket_age.to_bytes(4, 'big')
            identity_list.append(psk_identity)

            # Calculate expected binders size
            csuite = psk['csuite']
            if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
                hash_len = tls_constants.SHA_256_LEN
            if (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
                hash_len = tls_constants.SHA_384_LEN
            binders_size += hash_len+1 # the plus once for the size of PskBinderEntry that is 1B
        
        assert 33 <= binders_size <= 2**16-1
        identities = b''.join(identity_list) # concat all identities
        assert 7 <= len(identities) <= 2**16-1
        identities_len = len(identities).to_bytes(2, 'big')
        # After the identity list is made, we can now create the binders  
        binders_list = []
        for psk in psks_offered:
            # PreSharedKeyExtension == OfferedPsks bc we are client case
                # struct {
                # PskIdentity identities<7..2^16-1>;
                # PskBinderEntry binders<33..2^16-1>;
                # } OfferedPsks;
            expected_binders_len = 2 + binders_size
            offered_psks_mockup = identities_len + identities #+ binders_len + binders
            expected_psk_ext_len = (len(offered_psks_mockup) + expected_binders_len).to_bytes(2, 'big') # I know it is correct!
            psk_ext_mockup = psk_extension_type + expected_psk_ext_len + offered_psks_mockup

            # Transcript of chelo, extenstions formated up to identities with all corrects lengths
            extensions_mockup = extensions + psk_ext_mockup
            extensions_mockup_len = (len(extensions_mockup) + expected_binders_len).to_bytes(2, 'big')
            msg = chelo + extensions_mockup_len + extensions_mockup
            # The transcript of course is with the handshake...
            len_msg = (len(msg) + expected_binders_len).to_bytes(3, 'big')
            hs_msg_type = tls_constants.CHELO_TYPE.to_bytes(1, 'big')
            transcript = hs_msg_type + len_msg + msg
            
            csuite = psk['csuite']
            if (csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
                hash_len = tls_constants.SHA_256_LEN
            if (csuite == tls_constants.TLS_AES_256_GCM_SHA384):
                hash_len = tls_constants.SHA_384_LEN
            # PskBinderEntry is computed as the Finished message, but with the BaseKey being the binder_key included in the PSK dictionary.
            base_key = psk['binder key']
            finished_key = tls_crypto.hkdf_expand_label(csuite, base_key, b"finished", b"", hash_len)
            transcript_hash = tls_crypto.tls_transcript_hash(csuite, transcript)
            binder_tag = tls_crypto.tls_finished_mac(csuite, finished_key, transcript_hash)
            psk_binder_entry = len(binder_tag).to_bytes(1, 'big') + binder_tag # size correct
            #print(f"Client binder key: {base_key.hex()}")
            # print(f"Client transcript_hash: {transcript_hash.hex()}")
            binders_list.append(psk_binder_entry)

        binders = b''.join(binders_list) # concat all binders
        binders_len = len(binders).to_bytes(2, 'big')
        # Using the binder values create final PreSharedKeyExtension
        offered_psks_bytes = identities_len + identities + binders_len + binders
        psk_ext_len = len(offered_psks_bytes).to_bytes(2, 'big')
        assert expected_psk_ext_len == psk_ext_len
        psk_ext = psk_extension_type + psk_ext_len + offered_psks_bytes
        return psk_ext, psks_offered

    def tls_13_server_parse_psk_extension(self, psk_extension: bytes) -> Tuple[bytes, int]:
        cur_pos = 0
        identities_len = int.from_bytes(psk_extension[cur_pos:cur_pos+2], 'big')
        cur_pos += 2
        identities = psk_extension[cur_pos:cur_pos+identities_len]
        cur_pos += identities_len
        binders_len = int.from_bytes(psk_extension[cur_pos:cur_pos+2], 'big')
        cur_pos += 2
        binders = psk_extension[cur_pos:cur_pos+binders_len]
        cur_pos += binders_len
        if cur_pos != len(psk_extension):
            raise InvalidMessageStructureError()
                
        identity_list = []
        cur_ident_pos = 0
        while cur_ident_pos < len(identities):
            # First parse the identity
            identity_len = int.from_bytes(identities[cur_ident_pos:cur_ident_pos+2], 'big')
            cur_ident_pos += 2
            identity_bytes = identities[cur_ident_pos:cur_ident_pos+identity_len]
            cur_ident_pos += identity_len
            obfuscated_ticket_age = int.from_bytes(identities[cur_ident_pos:cur_ident_pos+4], 'big')
            cur_ident_pos += 4
            #print(identities[cur_ident_pos:cur_ident_pos+identity_len].hex())
            identity_list.append((identity_bytes, obfuscated_ticket_age))

        if cur_ident_pos != len(identities):
            raise InvalidMessageStructureError()

        binder_list = []
        cur_binder_pos = 0
        while cur_binder_pos < len(binders):
            # Then parse the binder for it
            binder_len = int.from_bytes(binders[cur_binder_pos:cur_binder_pos+1], 'big')
            cur_binder_pos += 1
            binder = binders[cur_binder_pos:cur_binder_pos+binder_len]
            cur_binder_pos += binder_len
            binder_list.append(binder)

        if cur_ident_pos != len(identities) or cur_binder_pos != len(binders) or len(binder_list) != len(identity_list): # Sanity check
            raise InvalidMessageStructureError()

        if len(identity_list) > 0:
            # There is a PSK, accept always early data
            self.accept_early_data = True
        # As we now have all identities and binders, lets do the checks
        for i, ((ticket, obfuscated_ticket_age), binder) in enumerate(zip(identity_list, binder_list)):
            mac_len = tls_constants.MAC_LEN[tls_constants.TLS_CHACHA20_POLY1305_SHA256]
            if (self.csuite == tls_constants.TLS_AES_128_GCM_SHA256) or (self.csuite == tls_constants.TLS_CHACHA20_POLY1305_SHA256):
                hash_len = tls_constants.SHA_256_LEN
            if (self.csuite == tls_constants.TLS_AES_256_GCM_SHA384):
                hash_len = tls_constants.SHA_384_LEN
            assert len(ticket) == 8 + hash_len + 4 + 4 + 2 + mac_len
            cur_pos = 0
            ticket_nonce = ticket[cur_pos:cur_pos+8]
            cur_pos += 8
            ctxt = ticket[cur_pos:cur_pos+hash_len + 4 + 4 + 2]
            cur_pos += hash_len + 4 + 4 + 2
            mac_tag = ticket[cur_pos:cur_pos+mac_len]
            cur_pos += mac_len
            if cur_pos != len(ticket):
                raise InvalidMessageStructureError()

            cipher = ChaCha20_Poly1305.new(key=self.server_static_enc_key, nonce=ticket_nonce) # Where from ticket_nonce???
            plaintext = cipher.decrypt_and_verify(ctxt, mac_tag)
            # get first csuite to know how long psk is
            csuite = int.from_bytes(plaintext[-2:], 'big')
            #plaintext = psk + age_add + lifetime + self.csuite.to_bytes(2, 'big') # csuite conversion correct?
            ptxt_cur_pos = 0
            ptxt_psk = plaintext[ptxt_cur_pos:ptxt_cur_pos+hash_len]
            ptxt_cur_pos += hash_len
            age_add = int.from_bytes(plaintext[ptxt_cur_pos:ptxt_cur_pos+4], 'big')
            ptxt_cur_pos += 4
            lifetime = int.from_bytes(plaintext[ptxt_cur_pos:ptxt_cur_pos+4], 'big')
            ptxt_cur_pos += 4
            ptxt_cur_pos += 2 # for the csuite we already read
            # Disregard as too old
            actual_age = (obfuscated_ticket_age - age_add) % 2**32
            if actual_age > lifetime and i == 0:
                # We should not accept early data in this case
                print(f"Server found old age --> rejects early data")
                self.accept_early_data = False
            if ptxt_cur_pos != len(plaintext):
                raise InvalidMessageStructureError()
            if csuite != self.csuite:
                print("Csuite mismatch")
                continue

            # Use PSK to calculate binder key
            early_secret = tls_crypto.tls_extract_secret(self.csuite, ptxt_psk, None)
            binder_key = tls_crypto.tls_derive_secret(self.csuite, early_secret, "res binder".encode(), "".encode())
            # Binder verification
            # base_key = binder_key
            finished_key = tls_crypto.hkdf_expand_label(csuite, binder_key, b"finished", b"", hash_len)
            binders_len_len_plus_len = 2 + binders_len
            truncated_transcript = self.transcript[:-binders_len_len_plus_len]
            transcript_hash = tls_crypto.tls_transcript_hash(csuite, truncated_transcript)
            try:
                tls_crypto.tls_finished_mac_verify(self.csuite, finished_key, transcript_hash, binder)
            except ValueError:
                # Critical error on verification
                raise BinderVerificationError()
            return ptxt_psk, i
        # None available
        raise TLSError()

    def tls_13_client_hello(self) -> bytes:
        chelo, extensions = self._tls_13_client_hello_chelo_ext()
        if len(self.psks) > 0:
            # Extend by PSK if we have any
            psk_mode_ext = self.tls_13_client_prep_psk_mode_extension()
            extensions += psk_mode_ext
            # Add EarlyDataIndication if there is any
            if self.early_data is not None:
                #print(f"Client adding EarlyDataIndication")
                extensions += tls_constants.EARLY_DATA_TYPE.to_bytes(2, 'big') + 0x0000.to_bytes(2, 'big')
            psk_ext, self.offered_psks = self.tls_13_client_add_psk_extension(chelo, extensions)
            extensions += psk_ext
        ext_len = len(extensions).to_bytes(tls_constants.EXT_LEN_LEN, byteorder='big')
        client_hello = chelo + ext_len + extensions
        return self._tls_13_client_hello_finish_off(client_hello)
    
    def tls_13_compute_client_early_key_iv(self) -> Tuple[bytes, bytes, int]:
        # FIRST WE NEED TO GENERATE A HANDSHAKE KEY
        if self.client_early_traffic_secret is None:
            raise StateConfusionError()
        early_data_key, early_data_iv = tls_crypto.tls_derive_key_iv(self.csuite, self.client_early_traffic_secret)
        return early_data_key, early_data_iv, self.csuite

    def tls_13_eoed(self) -> bytes:
        return self.attach_handshake_header(tls_constants.EOED_TYPE, b'')

    def tls_13_finished(self) -> bytes:
        transcript_hash = tls_crypto.tls_transcript_hash(
            self.csuite, self.transcript)
        finished_key = tls_crypto.tls_finished_key_derive(
            self.csuite, self.server_hs_traffic_secret)
        tag = tls_crypto.tls_finished_mac(self.csuite, finished_key, transcript_hash)
        fin_msg = self.attach_handshake_header(tls_constants.FINI_TYPE, tag)
        self.transcript = self.transcript + fin_msg
        if self.role == tls_constants.SERVER_FLAG:
            transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
            self.server_ap_traffic_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "s ap traffic".encode(), transcript_hash)
            self.client_ap_traffic_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "c ap traffic".encode(), transcript_hash)
        
        # Calculate the new resumption_master_secret 
        if self.role == tls_constants.CLIENT_FLAG:
            transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
            #print(f"{self.role} fin_msg {fin_msg.hex()}")
            self.resumption_master_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "res master".encode(), transcript_hash)
        
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
            if self.eoed_msg is not None:
                self.transcript = self.transcript + self.eoed_msg
        if self.role == tls_constants.SERVER_FLAG:
            transcript_hash = tls_crypto.tls_transcript_hash(self.csuite, self.transcript)
            self.resumption_master_secret = tls_crypto.tls_derive_secret(
                self.csuite, self.master_secret, "res master".encode(), transcript_hash)

    def tls_13_early_data_ext(self, data: bytes = b'') -> bytes:
        raise NotImplementedError()

    def tls_13_create_early_data(self):
        if self.offered_psks is not None:
            if len(self.early_data) > self.offered_psks[0]['max_data']:
                raise WrongLengthError()
            return self.early_data

    def tls_13_server_check_eoed(self, ptxt):
        self.transcript = self.transcript + ptxt
        self.process_handshake_header(tls_constants.EOED_TYPE, ptxt)

    def tls_13_client_prepare_eoed(self):
        eoed_msg = self.attach_handshake_header(tls_constants.EOED_TYPE, b"")
        self.eoed_msg = eoed_msg
        return eoed_msg

    def tls_13_early_data_secrets(self) -> bytes:
        if self.offered_psks is not None:
            psk = self.offered_psks[0]['PSK'] # as defined in the labsheet lets use the first psk
            self.csuite = self.offered_psks[0]['csuite'] # as defined in the labsheet lets use the first psk
            # Derive the secrets
            early_secret = tls_crypto.tls_extract_secret(self.csuite, psk, None)
            # Is this where the client_early_traffic_secret should be calculated??
            self.client_early_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, \
                early_secret, "c e traffic".encode(), self.transcript)
        
    def tls_13_server_enc_ext(self) -> bytes:
        if self.accept_early_data:
            msg = tls_constants.EARLY_DATA_TYPE.to_bytes(2, 'big') + 0x0000.to_bytes(2, 'big') # Empty extension
            msg = len(msg).to_bytes(2, 'big')+msg
        else:
            msg = 0x0000.to_bytes(2, 'big')
        enc_ext_msg = self.attach_handshake_header(tls_constants.ENEXT_TYPE, msg)
        self.transcript = self.transcript + enc_ext_msg
        return enc_ext_msg
        
    def tls_13_process_enc_ext(self, enc_ext_msg: bytes):
        enc_ext = self.process_handshake_header(tls_constants.ENEXT_TYPE, enc_ext_msg)
        self.transcript = self.transcript + enc_ext_msg
        if len(enc_ext) < 2:
            raise InvalidMessageStructureError()
        enc_ext_len = int.from_bytes(enc_ext[0:2], 'big')
        if enc_ext_len > 0 and int.from_bytes(enc_ext[2:4], 'big') == tls_constants.EARLY_DATA_TYPE:
            self.accept_early_data = True
            return True # say there was an EarlyDataIndication
        if enc_ext != 0x0000.to_bytes(2, 'big'):
            raise InvalidMessageStructureError()
        return False
    
    def _tls_13_server_get_remote_extensions_switch(self, ext_type, ext_bytes):
        # First the old ones
        if ext_type == tls_constants.SUPPORT_VERS_TYPE:
            return 'supported versions', ext_bytes
        if ext_type == tls_constants.SUPPORT_GROUPS_TYPE:
            return 'supported groups', ext_bytes
        if ext_type == tls_constants.KEY_SHARE_TYPE:
            return 'key share', ext_bytes
        if ext_type == tls_constants.SIG_ALGS_TYPE:
            return 'sig algs', ext_bytes
        # Addidions
        if ext_type == tls_constants.PSK_TYPE:
            return 'psk', ext_bytes
        if ext_type == tls_constants.PSK_KEX_MODE_TYPE:
            return 'psk mode', ext_bytes
        # 0-RTT maybe?
        if ext_type == tls_constants.EARLY_DATA_TYPE:
            return "0RTT", None
        #print(f"{self.role} got {ext_type} as an extension, but now known")
        return None, None

    def tls_13_server_get_remote_extensions(self) -> Dict[str, bytes]:
        return super().tls_13_server_get_remote_extensions()
    
    def tls_13_server_parse_psk_mode_ext(self, modes_bytes: bytes) -> bytes:
        modes_len = modes_bytes[0]
        modes = modes_bytes[1:modes_len+1]
        return modes

    def _tls_13_server_select_parameters_psk(self, remote_extensions: Dict[str, bytes]):
        # PSK probably in psk extension == PSK_TYPE
        psk_success = -1
        if "psk mode" in remote_extensions.keys() and "psk" in remote_extensions.keys():
            # psk and psk mode do exist
            # get the psk
            self.psk, self.selected_identity = self.tls_13_server_parse_psk_extension(remote_extensions['psk'])
            # get the mode
            psk_mode_bytes = remote_extensions["psk mode"]
            # TODO maybe switch over
            # self.use_keyshare = False
            # mode = self.tls_13_server_parse_psk_mode_ext(psk_mode_bytes)
            # psk_success = mode
            # if mode == tls_constants.PSK_DHE_KE_MODE:
            #     self.use_keyshare = True

            number_modes = int.from_bytes(psk_mode_bytes[0:1], 'big') # < ... > len def
            modes = []
            self.use_keyshare = False
            for i in range(number_modes):
                mode = int.from_bytes(psk_mode_bytes[1+i:2+i], 'big')
                psk_success = mode
                if mode == tls_constants.PSK_DHE_KE_MODE:
                    #PSK_KE_MODE = 0
                    #PSK_DHE_KE_MODE = 1 --> if possible choose
                    self.use_keyshare = True
                    return tls_constants.PSK_DHE_KE_MODE
                modes.append(mode) # 255 is 1B each
            assert len(modes) == number_modes
        return psk_success

    def tls_13_server_select_parameters(self, remote_extensions: Dict[str, bytes]):
        #This method sets the following fields to indicate the selected parameters:
        self._tls_13_server_select_parameters_supported(remote_extensions)
            # self.neg_version
            # self.neg_group
        self._tls_13_server_select_parameters_sig_csuite(remote_extensions)
            # self.signature
            # self.csuite
        psk_type = self._tls_13_server_select_parameters_psk(remote_extensions)
            # self.psk
            # self.selected_identity
            # self.use_keyshare
            # self.accept_early_data

        if "0RTT" not in remote_extensions.keys():
            # self.accept_early_data
            self.accept_early_data = False
        if self.accept_early_data: # so ther is a psk value chosen, the lifetime is good and we have 0RTT ext
            # self.client_early_data
            # Derive the secrets
            early_secret = tls_crypto.tls_extract_secret(self.csuite, self.psk, None)
            # Is this where the client_early_traffic_secret should be calculated??
            self.client_early_traffic_secret = tls_crypto.tls_derive_secret(self.csuite, \
            early_secret, "c e traffic".encode(), self.transcript)
        
        # Following would throw common group error...
        try:
            self._tls_13_server_select_parameters_dhe(remote_extensions)
                # self.neg_group
                # self.pub_key
                # self.ec_pub_key,
                # self.ec_sec_key
        except TLSError as e:
            if psk_type == tls_constants.PSK_KE_MODE: # As if psk only is a success, we do not need dhe
                raise e

    def _tls_13_prep_server_hello_create_extensions(self):
        # WE ATTACH ALL OUR EXTENSIONS but to the list
        extensions_list = []
        neg_vers_ext = tls_extensions.finish_support_vers_ext(self.neg_version)
        extensions_list.append(neg_vers_ext)
        neg_group_ext = tls_extensions.finish_support_group_ext(self.neg_group)
        extensions_list.append(neg_group_ext)
        if self.use_keyshare:
            supported_keyshare = tls_extensions.finish_keyshare_ext(self.pub_key, self.neg_group)
            extensions_list.append(supported_keyshare)
        if self.psk is not None:
            psk_bytes = self.selected_identity.to_bytes(2, 'big')
            psk_extension_type = tls_constants.PSK_TYPE.to_bytes(2, 'big')
            psk_ext_len = len(psk_bytes).to_bytes(2, 'big')
            psk_ext = psk_extension_type + psk_ext_len + psk_bytes
            extensions_list.append(psk_ext)
        extensions = b''.join(extensions_list)
        return extensions

    def _tls_13_prep_server_hello_derive_secrets(self):
        early_secret = tls_crypto.tls_extract_secret(self.csuite, self.psk, None)
        derived_early_secret = tls_crypto.tls_derive_secret(
            self.csuite, early_secret, "derived".encode(), "".encode())
        ecdh_secret = None
        if self.ec_pub_key is not None:
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
        # Creates the Server Hello message, updates the transcript, and sets the following fields:
        #     self.client_early_secret
        #     self.server_hs_traffic_secret
        #     self.client_hs_traffic_secret
        #     self.master_secret
        return super().tls_13_prep_server_hello()

    def _tls_13_process_server_hello_process_extensions(self, ext_type, ext_bytes):
        # First the old stuff
        super()._tls_13_process_server_hello_process_extensions(ext_type, ext_bytes)
        # Now do the new stuff
        if (ext_type == tls_constants.PSK_TYPE):
            # We are always in the server_hello stat in this function:
            # struct {
            # select (Handshake.msg_type) {
            # case client_hello: OfferedPsks;
            # case server_hello: uint16 selected_identity;
            if len(ext_bytes) != 2:
                raise InvalidMessageStructureError()
            # };
            # } PreSharedKeyExtension;
            self.selected_identity = int.from_bytes(ext_bytes, 'big')

    def _tls_13_process_server_hello_secret_derivation(self):
        # Compute the Diffie-Hellman secret value
        ecdh_secret = None
        psk = None
        if self.ec_pub_key is not None:
            # We did get a keyshare extension
            if self.neg_group not in self.ec_sec_keys.keys():
                raise NoCommonGroupError()
            ec_sec_key = self.ec_sec_keys[self.neg_group]
            ec_secret_point = tls_crypto.ec_dh(ec_sec_key, self.ec_pub_key)
            ecdh_secret = tls_crypto.point_to_secret(ec_secret_point, self.neg_group)
        if self.selected_identity is not None:
            psk = self.offered_psks[self.selected_identity]['PSK']
        # Derive the secrets
        self.early_secret = tls_crypto.tls_extract_secret(self.csuite, psk, None)
        derived_early_secret = tls_crypto.tls_derive_secret(
            self.csuite, self.early_secret, "derived".encode(), "".encode())
        
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
        super().tls_13_process_server_hello(shelo_msg)