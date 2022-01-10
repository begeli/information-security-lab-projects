#!/usr/bin/env python

'''
tls_application.py:
Implementation of the TLS 1.3 Protocol
'''

from socket import socket
from typing import Dict, List, Union
import tls_constants
from tls_error import WrongRoleError
import tls_state_machines as stm
import tls_psk_state_machines as pks_stm


class TLSConnection:
    'This is the high-level TLS API'

    def __init__(self, conn: socket):
        self.socket = conn
        self.role = None
        self.psks = None
        self.use_psk = None
        self.psk_modes = None
        self.stm = None
        self.early_data = None

    def connect(self, use_psk: bool = False, psks: List[Dict[str, Union[bytes, int]]] = [],
                psk_modes: List[int] = [], early_data: bytes = None):
        self.role = tls_constants.CLIENT_FLAG
        self.psks = psks
        self.use_psk = use_psk
        self.psk_modes = psk_modes
        self.early_data = early_data
        if use_psk:
            self.stm = pks_stm.TLS13ClientStateMachine(self.socket, use_psk, psks, psk_modes,
                                                       early_data)
        else:
            self.stm = stm.TLS13ClientStateMachine(self.socket)
        while not self.stm.connected():
            self.stm.transition()

    def accept(self, use_psk: bool = False, server_static_key: bytes = None):
        self.role = tls_constants.SERVER_FLAG
        self.use_psk = use_psk
        if use_psk:
            self.stm = pks_stm.TLS13ServerStateMachine(
                self.socket, self.use_psk, server_static_key)
        else:
            self.stm = stm.TLS13ServerStateMachine(self.socket)
        while not self.stm.connected():
            self.stm.transition()
        if hasattr(self.stm, 'client_early_data'):
            return self.stm.client_early_data

    def read(self) -> bytes:
        if self.stm.connected():
            msg_type = None
            while not msg_type == tls_constants.APPLICATION_TYPE:
                msg_type, msg = self.stm.transition()
            return msg

    def write(self, msg: bytes):
        if self.stm.connected():
            self.stm.transition(msg)

    def get_psks(self) -> List[Dict[str, Union[bytes, int]]]:
        if self.role == tls_constants.CLIENT_FLAG:
            return self.stm.psks
        raise WrongRoleError()
