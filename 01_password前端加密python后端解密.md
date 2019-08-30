# 前端代码
```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
    <script type="text/javascript" src="crypto-js.js"></script>

</head>
<body>

<script type="text/javascript">

          // 1、Encrypt 加密
        /*var cipherText = CryptoJS.AES.encrypt(
          "Data that needs to be encrypted!",
          "secretkey123"
        ).toString();
        console.log(cipherText)*/
        cipherText = "U2FsdGVkX1/qoJ+NEuRARcUb+NbMLW8oXh8Fwua7ytPg0QxWQID5fCPvytU/KKZQoKA01UgNsDBgrANIO4ghYA=="
        // 2、Decrypt 解密
        var bytes = CryptoJS.AES.decrypt(cipherText, "secretkey123");
        var originalText = bytes.toString(CryptoJS.enc.Utf8);
        console.log(originalText, typeof originalText); // ‘my message‘

        //U2FsdGVkX19uISqARmxcNp0HM/k3UoyHgwG0ufs0ZbUeRHKDE6eCgzUDwJt4WzEw3HMAtBniaMxlS19GiLowSA==
        //U2FsdGVkX19Y9wPkugnHJekRPp9cq6zZ0LHomqbcY4X7rxUvouse1ah1EcPG/3JmF7Vw1FmoVM6LSA3goQw5Rg==
        //U2FsdGVkX1/qoJ+NEuRARcUb+NbMLW8oXh8Fwua7ytPg0QxWQID5fCPvytU/KKZQoKA01UgNsDBgrANIO4ghYA==

</script>

</body>
</html>
```

# 后端 （python)
- 需要安装的模块 pycryto

```
# -*- coding:UTF-8 -*-
from Crypto import Random
from Crypto.Cipher import AES
import base64
from hashlib import md5


class EncDecAES(object):
    def pad(self, data):
        length = 16 - (len(data) % 16)
        return data + (chr(length) * length).encode()

    def unpad(self, data):
        return data[:-(data[-1] if type(data[-1]) == int else ord(data[-1]))]

    def bytes_to_key(self, data, salt, output=48):
        assert len(salt) == 8, len(salt)
        data += salt
        key = md5(data).digest()
        final_key = key
        while len(final_key) < output:
            key = md5(key + data).digest()
            final_key += key
        return final_key[:output]

    def encrypt(self, message, passphrase):
        salt = Random.new().read(8)
        key_iv = self.bytes_to_key(passphrase, salt, 32 + 16)
        key = key_iv[:32]
        iv = key_iv[32:]
        aes = AES.new(key, AES.MODE_CBC, iv)
        return base64.b64encode(b"Salted__" + salt + aes.encrypt(self.pad(message)))

    def decrypt(self, encrypted, passphrase):
        encrypted = base64.b64decode(encrypted)
        assert encrypted[0:8] == b"Salted__"
        salt = encrypted[8:16]
        key_iv = self.bytes_to_key(passphrase, salt, 32 + 16)
        key = key_iv[:32]
        iv = key_iv[32:]
        aes = AES.new(key, AES.MODE_CBC, iv)
        return self.unpad(aes.decrypt(encrypted[16:]))


if  __name__ == '__name__':
    data = 'Data that needs to be encrypted!'  # 要加密的数据
    passphrase = "secretkey123" # 加密解密用的秘钥

    # 1、加密
    encMsg = EncDecAES().encrypt(data, passphrase)
    print encMsg  # U2FsdGVkX1/GaKnTiu4lQ6zuCwHB+SyN9ARgSZXLpJznjY38+cApNYL0qTdgQ3Iv

    # 2、解密
    decMsg = EncDecAES().decrypt(encMsg, passphrase)
    print decMsg  # Data that needs to be encrypted
```
