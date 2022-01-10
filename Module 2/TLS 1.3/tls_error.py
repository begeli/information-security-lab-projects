#!/usr/bin/env python

'''
tls_extensions.py:
Contains the functions needed to raise errors throughout the TLS protocol
'''

import tls_constants

class TLSError(Exception):
    pass

class NoCommonGroupError(TLSError):
    pass

class NoCommonCiphersuiteError(TLSError):
    pass

class NoCommonVersionError(TLSError):
    pass

class NoCommonSignatureError(TLSError):
    pass

class StateConfusionError(TLSError):
    pass

class WrongLengthError(TLSError):
    pass

class VerificationFailure(TLSError):
    pass

class InvalidMessageStructureError(TLSError):
    pass

class UnexpectedMessageError(TLSError):
    pass

class WrongRoleError(TLSError):
    pass

class WrongVersionError(TLSError):
    pass

class BinderVerificationError(TLSError):
    pass

class IllegalParameterError(Exception):
    def __init__(self):
        super().__init__()
        print("IllegalParameterError: Some Attribute did not verify correctly")

def tls_prepare_alert(type_int):
    alert_level = tls_constants.TLS_ERROR_FATAL_LVL.to_bytes(1, 'big')
    alert_type = type_int.to_bytes(1, 'big')
    alert_msg = alert_level + alert_type
    return alert_msg

def tls_read_alert(alert_msg):
    alert_type = alert_msg[1]
    if (alert_type == tls_constants.TLS_ILLEGAL_PARA):
        print("Server didn't like a parameter!")
        raise IllegalParameterError
