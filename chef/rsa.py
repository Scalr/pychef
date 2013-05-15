from M2Crypto import RSA, BIO

class SSLError(Exception):
    """An error in OpenSSL."""

    def __init__(self, message, *args):
        message = message%args
        super(SSLError, self).__init__(message)


RSA_F4 = 0x10001


class Key(object):
    """An OpenSSL RSA key."""

    def __init__(self, fp=None):
        self.key = None
        self.public = False
        if not fp:
            return
        if isinstance(fp, basestring):
            if fp.startswith('-----'):
                # PEM formatted text
                self.raw = fp
            else:
                self.raw = open(fp, 'rb').read()
        else:
            self.raw = fp.read()
        self._load_key()

    def _load_key(self):
        try:
            self.key = RSA.load_key_string(self.raw, lambda x: None)
        except RSA.RSAError:
            self.public = True
            if self.raw.strip().splitlines()[0] == '-----BEGIN RSA PUBLIC KEY-----':
                self.raw = self.raw.replace('-----BEGIN RSA PUBLIC KEY-----', '-----BEGIN PUBLIC KEY-----')
                self.raw = self.raw.replace('-----END RSA PUBLIC KEY-----', '-----END PUBLIC KEY-----')
            bio = BIO.MemoryBuffer(self.raw)
            try:
                self.key = RSA.load_pub_key_bio(bio)
            except RSA.RSAError:
                raise SSLError('Unable to load RSA key')


    @classmethod
    def generate(cls, size=1024, exp=RSA_F4):
        self = cls()
        self.key = RSA.gen_key(size, exp)
        return self

    def private_encrypt(self, value, padding=RSA.pkcs1_padding):
        if self.public:
            raise SSLError('private method cannot be used on a public key')
        output = self.key.private_encrypt(value, padding)
        return output

    def public_decrypt(self, value, padding=RSA.pkcs1_padding):
        output = self.key.public_decrypt(value, padding)
        return output

    def private_export(self):
        if self.public:
            raise SSLError('private method cannot be used on a public key')
        pem = self.key.as_pem(cipher=None, callback=lambda x: None)
        return pem

    def public_export(self):
        bio = BIO.MemoryBuffer()
        self.key.save_pub_key_bio(bio)
        pem = bio.read()
        return pem
