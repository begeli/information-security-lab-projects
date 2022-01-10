import socket
from typing import Dict, List, Union
from enum import Enum, auto, unique
from tls_error import (TLSError, InvalidMessageStructureError, WrongRoleError)
from tls_psk_handshake import PSKHandshake
import tls_constants
import tls_record_layer


@unique
class ServerState(Enum):
    START = auto()
    RECVD_CH = auto()
    NEGOTIATED = auto()
    WAIT_FLIGHT2 = auto()
    WAIT_EOED = auto()
    WAIT_FINISHED = auto()
    CONNECTED = auto()


@unique
class ClientState(Enum):
    START = auto()
    WAIT_SH = auto()
    WAIT_EE = auto()
    WAIT_CERT_CR = auto()
    WAIT_CV = auto()
    WAIT_FINISHED = auto()
    CONNECTED = auto()


class TLS13StateMachine():
    def __init__(self, conn: socket.socket):
        super().__init__()
        self.socket = conn
        self.state = None
        self.handshake = None

        self.csuite = None
        self.server_hs_traffic_key = None
        self.server_hs_traffic_iv = None
        self.client_hs_traffic_key = None
        self.client_hs_traffic_iv = None
        self.send_hs_enc_connect = None
        self.recv_hs_enc_connect = None

        self.server_ap_traffic_key = None
        self.server_ap_traffic_iv = None
        self.client_ap_traffic_key = None
        self.client_ap_traffic_iv = None
        self.send_ap_enc_connect = None
        self.recv_ap_enc_connect = None

    def _send(self, msg: bytes):
        sent = 0
        while sent < len(msg):
            s = self.socket.send(msg[sent:])
            if s == 0:
                raise RuntimeError('broken connection')
            sent += s

    def _receive(self) -> bytes:
        # Assume Record protocol: read the the first bytes until the length can be read.
        buffer = bytearray(tls_constants.MAX_RECORD_LEN)
        buffer_view = memoryview(buffer)
        to_read = tls_constants.RECORD_PREFIX_LEN
        read = 0
        prefix = buffer_view[:to_read]
        while read < to_read:
            r = self.socket.recv_into(prefix[read:], to_read - read)
            if r == 0:
                raise RuntimeError('broken connection')
            read += r

        # Read the remainder of the message
        to_read = int.from_bytes(prefix[3:5], 'big')
        read = 0
        data = buffer_view[tls_constants.RECORD_PREFIX_LEN: to_read +
                           tls_constants.RECORD_PREFIX_LEN]
        while read < to_read:
            r = self.socket.recv_into(data[read:], to_read - read)
            if r == 0:
                raise RuntimeError('broken connection')
            read += r

        return buffer[:to_read+tls_constants.RECORD_PREFIX_LEN]

    def send_enc_message(self, plaintext):
        tls_enc_msg = self.send_ap_enc_connect.enc_packet(plaintext)
        return tls_enc_msg

    def recv_enc_message(self, ciphertext):
        _, ptxt_msg = self.recv_ap_enc_connect.dec_packet(ciphertext)
        return ptxt_msg

    def transition(self, write: bytes = None):
        pass


class TLS13ServerStateMachine(TLS13StateMachine):
    def __init__(self, conn: socket.socket, use_psk: bool, server_static_key: bytes) -> None:
        super().__init__(conn)
        self.state = ServerState.START
        self.role = tls_constants.SERVER_FLAG
        self.use_psk = use_psk
        self.server_static_enc_key = server_static_key

    def finish_tls_connection_server(self, client_messages: bytes):
        if self.role != tls_constants.SERVER_FLAG:
            raise WrongRoleError()
        curr_pos = 0
        curr_msg = client_messages
        msg_type = int.from_bytes(curr_msg[:tls_constants.MSG_TYPE_LEN], 'big')
        curr_pos = curr_pos + tls_constants.MSG_TYPE_LEN
        msg_len = int.from_bytes(
            curr_msg[curr_pos:curr_pos + tls_constants.MSG_LEN_LEN], 'big')
        if msg_type == tls_constants.APPLICATION_TYPE:
            type, ptxt_msg = self.recv_hs_enc_connect.dec_packet(
                curr_msg[:msg_len])
            if type != tls_constants.HANDSHAKE_TYPE:
                raise InvalidMessageStructureError()
            msg_type = ptxt_msg[0]
            if msg_type == tls_constants.FINI_TYPE:
                self.handshake.tls_13_process_finished(ptxt_msg)

    def transition(self, write: bytes = None):
        if self.state == ServerState.START:
            msg_bytes = self._receive()
            content_type, msg = tls_record_layer.read_TLSPlaintext(msg_bytes)
            if content_type == tls_constants.HANDSHAKE_TYPE:
                self.handshake = PSKHandshake(tls_constants.SERVER_SUPPORTED_CIPHERSUITES,
                                              tls_constants.SERVER_SUPPORTED_EXTENSIONS,
                                              self.role, self.use_psk,
                                              server_static_enc_key=self.server_static_enc_key)
                try:
                    self.handshake.tls_13_process_client_hello(msg)
                except InvalidMessageStructureError:
                    # Not a client Hello, do nothing and return
                    return
                self.state = ServerState.RECVD_CH
            else:
                pass
        elif self.state == ServerState.RECVD_CH:
            try:
                remote_extensions = self.handshake.tls_13_server_get_remote_extensions()
                self.handshake.tls_13_server_select_parameters(
                    remote_extensions)
            except TLSError as error:
                raise error
            self.state = ServerState.NEGOTIATED
        elif self.state == ServerState.NEGOTIATED:
            msg = self.handshake.tls_13_prep_server_hello()

            # Create fields to receive early data
            if self.handshake.accept_early_data:
                self.early_data_key, self.early_data_iv, self.csuite = \
                    self.handshake.tls_13_compute_client_early_key_iv()

                self.recv_early_enc_connect = tls_record_layer.ProtectedRecordLayer(
                    self.early_data_key, self.early_data_iv, self.csuite,
                    tls_constants.RECORD_READ)

                self.send_early_enc_connect = tls_record_layer.ProtectedRecordLayer(
                    self.early_data_key, self.early_data_iv, self.csuite,
                    tls_constants.RECORD_WRITE)

            tls_server_hello = tls_record_layer.create_TLSPlaintext(
                msg, tls_constants.HANDSHAKE_TYPE)
            tls_ccs_msg = tls_record_layer.create_ccs_packet()

            (self.server_hs_traffic_key, self.server_hs_traffic_iv,
             self.csuite) = self.handshake.tls_13_compute_server_hs_key_iv()

            self.send_hs_enc_connect = tls_record_layer.ProtectedRecordLayer(
                self.server_hs_traffic_key, self.server_hs_traffic_iv, self.csuite,
                tls_constants.RECORD_WRITE)

            (self.client_hs_traffic_key, self.client_hs_traffic_iv,
             self.csuite) = self.handshake.tls_13_compute_client_hs_key_iv()

            self.recv_hs_enc_connect = tls_record_layer.ProtectedRecordLayer(
                self.client_hs_traffic_key, self.client_hs_traffic_iv, self.csuite,
                tls_constants.RECORD_READ)

            enc_ext_msg = self.handshake.tls_13_server_enc_ext()
            tls_enc_ext_msg = self.send_hs_enc_connect.enc_packet(
                enc_ext_msg, tls_constants.HANDSHAKE_TYPE)
            self._send(tls_server_hello + tls_ccs_msg + tls_enc_ext_msg)

            if not self.use_psk:
                scert_msg = self.handshake.tls_13_server_cert()
                tls_scert_msg = self.send_hs_enc_connect.enc_packet(
                    scert_msg, tls_constants.HANDSHAKE_TYPE)
                cert_verify_msg = self.handshake.tls_13_server_cert_verify()
                tls_cert_verify_msg = self.send_hs_enc_connect.enc_packet(
                    cert_verify_msg, tls_constants.HANDSHAKE_TYPE)
                self._send(tls_scert_msg + tls_cert_verify_msg)

            fin_msg = self.handshake.tls_13_finished()
            tls_fin_msg = self.send_hs_enc_connect.enc_packet(
                fin_msg, tls_constants.HANDSHAKE_TYPE)

            self._send(tls_fin_msg)

            (self.server_ap_traffic_key, self.server_ap_traffic_iv,
             self.csuite) = self.handshake.tls_13_compute_server_ap_key_iv()

            self.send_ap_enc_connect = tls_record_layer.ProtectedRecordLayer(
                self.server_ap_traffic_key, self.server_ap_traffic_iv, self.csuite,
                tls_constants.RECORD_WRITE)

            (self.client_ap_traffic_key, self.client_ap_traffic_iv,
             self.csuite) = self.handshake.tls_13_compute_client_ap_key_iv()

            self.recv_ap_enc_connect = tls_record_layer.ProtectedRecordLayer(
                self.client_ap_traffic_key, self.client_ap_traffic_iv, self.csuite,
                tls_constants.RECORD_READ)

            # If we accept early data we should go to WAIT_EOED state
            if self.handshake.accept_early_data:
                self.state = ServerState.WAIT_EOED
            else:
                self.state = ServerState.WAIT_FLIGHT2
        elif self.state == ServerState.WAIT_EOED:
            enc_early_msg = self._receive()
            msg_type, early_msg = self.recv_early_enc_connect.dec_packet(enc_early_msg)

            # We received the end of early data message
            if msg_type == tls_constants.APPLICATION_TYPE:
                self.handshake.client_early_data = early_msg
                self.client_early_data = early_msg
            elif msg_type == tls_constants.HANDSHAKE_TYPE:
                self.state = ServerState.WAIT_FLIGHT2
            else:
                pass

        elif self.state == ServerState.WAIT_FLIGHT2:
            self.state = ServerState.WAIT_FINISHED
        elif self.state == ServerState.WAIT_FINISHED:
            msg_bytes = self._receive()
            self.finish_tls_connection_server(msg_bytes)

            # Send the session ticket
            if self.use_psk:
                session_ticket = self.handshake.tls_13_server_new_session_ticket()
                ctxt = self.send_ap_enc_connect.enc_packet(session_ticket, tls_constants.NEWST_TYPE)
                self._send(ctxt)

            self.state = ServerState.CONNECTED
        elif self.state == ServerState.CONNECTED:
            if write is None:
                # We don't support renegotiation, so we can don't read if we want to write.
                msg_bytes = self._receive()
                content_type, msg = tls_record_layer.read_TLSPlaintext(
                    msg_bytes)
                if content_type == tls_constants.APPLICATION_TYPE:
                    msg_type, ptxt = self.recv_ap_enc_connect.dec_packet(
                        msg_bytes)
                    if msg_type == tls_constants.APPLICATION_TYPE:
                        return msg_type, ptxt
                    elif msg_type == tls_constants.HANDSHAKE_TYPE:
                        pass
                    elif msg_type == tls_constants.ALERT_TYPE:
                        pass
                    else:
                        pass
                else:
                    pass
            else:
                ctxt = self.send_enc_message(write)
                self._send(ctxt)
        else:
            pass

        return (None, None)

    def connected(self) -> bool:
        return self.state == ServerState.CONNECTED


class TLS13ClientStateMachine(TLS13StateMachine):
    def __init__(self, conn: socket.socket, use_psk: bool,
                 psks: List[Dict[str, Union[bytes, int]]], psk_modes: List[int],
                 early_data: bytes) -> None:
        super().__init__(conn)
        self.state = ClientState.START
        self.role = tls_constants.CLIENT_FLAG
        self.use_psk = use_psk
        self.psks = psks
        self.supported_psk_modes = psk_modes
        self.early_data = early_data

    def begin_tls_handshake(self):
        # Set the psks that are available to the client
        used_psks = self.psks if self.use_psk else None
        used_early_data = self.early_data if self.use_psk and len(used_psks) > 0 else None
        self.handshake = PSKHandshake(tls_constants.CLIENT_SUPPORTED_CIPHERSUITES,
                                      tls_constants.CLIENT_SUPPORTED_EXTENSIONS,
                                      self.role, used_psks, self.supported_psk_modes,
                                      early_data=used_early_data)
        chelo_msg = self.handshake.tls_13_client_hello()
        tls_client_hello = tls_record_layer.create_TLSPlaintext(
            chelo_msg, tls_constants.HANDSHAKE_TYPE)

        self._send(tls_client_hello)

    def transition(self, write: bytes = None):
        if self.state == ClientState.START:
            self.begin_tls_handshake()
            # Send the early data here
            if self.handshake.early_data:
                self.early_data_key, self.early_data_iv, self.csuite = \
                    self.handshake.tls_13_compute_client_early_key_iv()

                self.recv_early_enc_connect = tls_record_layer.ProtectedRecordLayer(
                    self.early_data_key, self.early_data_iv, self.csuite,
                    tls_constants.RECORD_READ)

                self.send_early_enc_connect = tls_record_layer.ProtectedRecordLayer(
                    self.early_data_key, self.early_data_iv, self.csuite,
                    tls_constants.RECORD_WRITE)

                # Don't send more data then allowed by the server
                max_data_size = self.psks[0]['max_data']
                early_msg = self.early_data \
                    if len(self.early_data) <= max_data_size \
                    else self.early_data[:max_data_size]
                enc_early_msg = \
                    self.send_early_enc_connect.enc_packet(early_msg, tls_constants.APPLICATION_TYPE)
                # Send encrypted message
                self._send(enc_early_msg)

            self.state = ClientState.WAIT_SH
        elif self.state == ClientState.WAIT_SH:
            msg_bytes = self._receive()
            content_type, msg = tls_record_layer.read_TLSPlaintext(msg_bytes)
            if content_type == tls_constants.HANDSHAKE_TYPE:
                try:
                    self.handshake.tls_13_process_server_hello(msg)
                except InvalidMessageStructureError as error:
                    raise error
                (self.server_hs_traffic_key, self.server_hs_traffic_iv,
                 self.csuite) = self.handshake.tls_13_compute_server_hs_key_iv()

                (self.client_hs_traffic_key, self.client_hs_traffic_iv,
                 self.csuite) = self.handshake.tls_13_compute_client_hs_key_iv()

                self.recv_hs_enc_connect = tls_record_layer.ProtectedRecordLayer(
                    self.server_hs_traffic_key, self.server_hs_traffic_iv, self.csuite,
                    tls_constants.RECORD_READ)

                self.send_hs_enc_connect = tls_record_layer.ProtectedRecordLayer(
                    self.client_hs_traffic_key, self.client_hs_traffic_iv, self.csuite,
                    tls_constants.RECORD_WRITE)
                self.state = ClientState.WAIT_EE
            elif content_type == tls_constants.ALERT_TYPE:
                pass
            elif content_type == tls_constants.CHANGE_TYPE:
                # Do Nothing
                pass
            else:
                raise RuntimeError(
                    f'Unexpected Content Type {content_type} {msg_bytes}')
        elif self.state == ClientState.WAIT_EE:
            msg_bytes = self._receive()
            content_type, msg = tls_record_layer.read_TLSPlaintext(msg_bytes)
            if content_type == tls_constants.APPLICATION_TYPE:
                msg_type, ptxt_msg = self.recv_hs_enc_connect.dec_packet(
                    msg_bytes)
                try:
                    if (msg_type == tls_constants.HANDSHAKE_TYPE):
                        self.handshake.tls_13_process_enc_ext(ptxt_msg)
                    else:
                        raise RuntimeError(
                            f'Unexpected Message Type {msg_type} {ptxt_msg}')
                except InvalidMessageStructureError as error:
                    raise error

                # Skip waiting for certificate if we use psks
                if self.use_psk:
                    self.state = ClientState.WAIT_FINISHED
                else:
                    self.state = ClientState.WAIT_CERT_CR
            elif content_type == tls_constants.ALERT_TYPE:
                pass
            elif content_type == tls_constants.CHANGE_TYPE:
                # Do Nothing
                pass
            else:
                raise RuntimeError(
                    f'Unexpected Content Type {content_type} {msg_bytes}')
        elif self.state == ClientState.WAIT_CERT_CR:
            msg_bytes = self._receive()
            content_type, msg = tls_record_layer.read_TLSPlaintext(msg_bytes)
            if content_type == tls_constants.APPLICATION_TYPE:
                msg_type, ptxt_msg = self.recv_hs_enc_connect.dec_packet(
                    msg_bytes)
                try:
                    if (msg_type == tls_constants.HANDSHAKE_TYPE):
                        self.handshake.tls_13_process_server_cert(
                            ptxt_msg)
                    else:
                        raise RuntimeError('Unexpected Message Type')
                except InvalidMessageStructureError as error:
                    raise error
                self.state = ClientState.WAIT_CV
            elif content_type == tls_constants.ALERT_TYPE:
                pass
            elif content_type == tls_constants.CHANGE_TYPE:
                # Do Nothing
                pass
            else:
                raise RuntimeError('Unexpected Content Type')
        elif self.state == ClientState.WAIT_CV:
            msg_bytes = self._receive()
            content_type, msg = tls_record_layer.read_TLSPlaintext(msg_bytes)
            if content_type == tls_constants.APPLICATION_TYPE:
                msg_type, ptxt_msg = self.recv_hs_enc_connect.dec_packet(
                    msg_bytes)
                try:
                    if msg_type == tls_constants.HANDSHAKE_TYPE:
                        self.handshake.tls_13_process_server_cert_verify(
                            ptxt_msg)
                    else:
                        raise RuntimeError('Unexpected Message Type')
                except InvalidMessageStructureError as error:
                    raise error
                self.state = ClientState.WAIT_FINISHED
            elif content_type == tls_constants.ALERT_TYPE:
                pass
            elif content_type == tls_constants.CHANGE_TYPE:
                # Do Nothing
                pass
            else:
                raise RuntimeError('Unexpected Content Type')
        elif self.state == ClientState.WAIT_FINISHED:
            msg_bytes = self._receive()
            content_type, msg = tls_record_layer.read_TLSPlaintext(msg_bytes)
            if content_type == tls_constants.APPLICATION_TYPE:
                msg_type, ptxt_msg = self.recv_hs_enc_connect.dec_packet(
                    msg_bytes)
                try:
                    if msg_type == tls_constants.HANDSHAKE_TYPE:
                        self.handshake.tls_13_process_finished(ptxt_msg)

                        # Send end of early data
                        if self.handshake.early_data:
                            eoed_msg = self.handshake.tls_13_eoed()
                            enc_eoed_msg = \
                                self.send_early_enc_connect.enc_packet(eoed_msg, tls_constants.HANDSHAKE_TYPE)
                            self._send(enc_eoed_msg)

                        fin_msg = self.handshake.tls_13_finished()
                        self._send(self.send_hs_enc_connect.enc_packet(
                            fin_msg, tls_constants.HANDSHAKE_TYPE))
                    else:
                        raise RuntimeError('Unexpected Message Type')
                except InvalidMessageStructureError as error:
                    raise error

                (self.server_ap_traffic_key, self.server_ap_traffic_iv,
                 self.csuite) = self.handshake.tls_13_compute_server_ap_key_iv()
                (self.client_ap_traffic_key, self.client_ap_traffic_iv,
                 self.csuite) = self.handshake.tls_13_compute_client_ap_key_iv()
                self.recv_ap_enc_connect = tls_record_layer.ProtectedRecordLayer(
                    self.server_ap_traffic_key, self.server_ap_traffic_iv, self.csuite,
                    tls_constants.RECORD_READ)
                self.send_ap_enc_connect = tls_record_layer.ProtectedRecordLayer(
                    self.client_ap_traffic_key, self.client_ap_traffic_iv, self.csuite,
                    tls_constants.RECORD_WRITE)

                self.state = ClientState.CONNECTED

                if self.use_psk:
                    ctxt = self._receive()
                    _, ptxt = self.recv_ap_enc_connect.dec_packet(ctxt)
                    PSK_dict = self.handshake.tls_13_client_parse_new_session_ticket(ptxt)
                    self.psks.append(PSK_dict)

            elif content_type == tls_constants.ALERT_TYPE:
                pass
            elif content_type == tls_constants.CHANGE_TYPE:
                # Do Nothing
                pass
            else:
                raise RuntimeError('Unexpected Content Type')
        elif self.state == ClientState.CONNECTED:
            if write is None:
                msg_bytes = self._receive()
                content_type, msg = tls_record_layer.read_TLSPlaintext(
                    msg_bytes)
                if content_type == tls_constants.APPLICATION_TYPE:
                    msg_type, ptxt = self.recv_ap_enc_connect.dec_packet(
                        msg_bytes)
                    if msg_type == tls_constants.APPLICATION_TYPE:
                        return msg_type, ptxt
                    elif msg_type == tls_constants.HANDSHAKE_TYPE:
                        pass
                    elif msg_type == tls_constants.ALERT_TYPE:
                        pass
                    else:
                        pass
                else:
                    pass
            else:
                # We don't support renegotiation, so we don't read if we want to write.
                ctxt = self.send_enc_message(write)
                self._send(ctxt)
        else:
            pass
        return None

    def connected(self) -> bool:
        return self.state == ClientState.CONNECTED
