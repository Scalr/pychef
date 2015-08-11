import six
import sys
import OpenSSL

_lib = OpenSSL._util.lib
_ffi = OpenSSL._util.ffi

NULL = _ffi.NULL
RSA_PKCS1_PADDING = 1
RSA_F4 = 0x10001

class SSLError(Exception):

    """An error in OpenSSL."""

    def __init__(self, message, *args):
        message = message % args
        err = _lib.ERR_get_error()
        if err:
            message += ':'
        while err:
            buf = _ffi.new('char[]', 120)
            _lib.ERR_error_string_n(err, buf, 120)
            if six.PY3:
                message += '\n%s' % b''.join(buf).decode('utf-8')
            else:
                message += '\n%s' % ''.join(buf)
            err = _lib.ERR_get_error()
        super(SSLError, self).__init__(message)


def BIO_reset(b):
    return _lib.BIO_ctrl(b, 1, 0, NULL)


class Key(object):

    """An OpenSSL RSA key."""

    def __init__(self, fp=None):
        self.key = None
        self.public = False
        if not fp:
            return
        if isinstance(fp, six.binary_type) and fp.startswith('-----'.encode()):
            # PEM formatted text
            self.raw = fp
        elif isinstance(fp, six.string_types):
            self.raw = open(fp, 'rb').read()
        else:
            self.raw = fp.read()
        self._load_key()

    def _load_key(self):
        buf = _ffi.new("char[]", self.raw)
        bio = _lib.BIO_new_mem_buf(buf, len(buf))
        try:
            self.key = _lib.PEM_read_bio_RSAPrivateKey(bio,
                                                       _ffi.new('RSA**'),
                                                       _ffi.new('char *'),
                                                       _ffi.new('char *'))
            if not self.key:
                BIO_reset(bio)
                self.public = True
                self.key = _lib.PEM_read_bio_RSAPublicKey(bio,
                                                          _ffi.new('RSA**'),
                                                          _ffi.new('char *'),
                                                          _ffi.new('char *'))
            if not self.key:
                raise SSLError('Unable to load RSA key')
        finally:
            _lib.BIO_free(bio)

    @classmethod
    def generate(cls, size=1024, exp=_lib.RSA_F4):
        self = cls()
        key = _lib.RSA_new()
        exponent = _lib.BN_new()
        exponent = _ffi.gc(exponent, _lib.BN_free)
        _lib.BN_set_word(exponent, exp)
        res = _lib.RSA_generate_key_ex(key, size, exponent, NULL)
        if res == 0:
            raise SSLError('Unable to generate key')
        self.key = key
        return self

    def private_encrypt(self, value, padding=RSA_PKCS1_PADDING):
        if self.public:
            raise SSLError('private method cannot be used on a public key')
        if six.PY3 and not isinstance(value, bytes):
            value = bytes(value, encoding='utf-8')
        else:
            value = str(value)
        buf = _ffi.new('char[%i]' % len(value), value)
        size = _lib.RSA_size(self.key)
        output = _ffi.new('char[]', size)
        ret = _lib.RSA_private_encrypt(len(buf), buf, output, self.key, padding)
        if ret <= 0:
            raise SSLError('Unable to encrypt data')
        if six.PY3:
            return b''.join(output[0:ret])
        else:
            return ''.join(output[0:ret])

    def public_decrypt(self, value, padding=RSA_PKCS1_PADDING):
        if six.PY3 and not isinstance(value, bytes):
            value = bytes(value, encoding='utf-8')
        buf = _ffi.new('char[%i]' % len(value), value)
        size = _lib.RSA_size(self.key)
        output = _ffi.new('char[]', size)
        ret = _lib.RSA_public_decrypt(len(buf), buf, output, self.key, padding)
        if ret <= 0:
            raise SSLError('Unable to decrypt data')
        if six.PY3:
            return b''.join(output[0:ret]).decode('utf-8')
        else:
            return ''.join(output[0:ret])

    def private_export(self):
        if self.public:
            raise SSLError('private method cannot be used on a public key')
        bio = _lib.BIO_new(_lib.BIO_s_mem())
        _lib.PEM_write_bio_RSAPrivateKey(bio, self.key, NULL, NULL, 0, NULL, NULL)
        pem = OpenSSL.crypto._bio_to_string(bio)
        return pem

    def public_export(self):
        bio = _lib.BIO_new(_lib.BIO_s_mem())
        _lib.PEM_write_bio_RSAPublicKey(bio, self.key)
        pem = OpenSSL.crypto._bio_to_string(bio)
        return pem

    def __del__(self):
        if self.key and _lib.RSA_free:
            _lib.RSA_free(self.key)
