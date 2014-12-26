import time
import hmac
import random
import string
import hashlib
import struct
import base64

__author__ = 'comyn'


def totp_verify(secret, code_attempt):
    tm = int(time.time() / 30)
    secretkey = base64.b32decode(secret)
    # try 30 seconds behind and ahead as well
    for ix in [-1, 0, 1]:
        # convert timestamp to raw bytes
        b = struct.pack(">q", tm + ix)
        # generate HMAC-SHA1 from timestamp based on secret key
        hm = hmac.HMAC(secretkey, b, hashlib.sha1).digest()
        # extract 4 bytes from digest based on LSB
        offset = ord(hm[-1]) & 0x0F
        truncatedHash = hm[offset:offset + 4]
        # get the code from it
        code = struct.unpack(">L", truncatedHash)[0]
        code &= 0x7FFFFFFF
        code %= 1000000
        if ("%06d" % code) == str(code_attempt):
            return True
    return False


def random_str(length, lower=False):
    if lower:
        return ''.join(random.sample(string.ascii_lowercase + string.digits, length))
    return ''.join(random.sample(string.ascii_letters + string.digits, length))