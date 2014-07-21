PlainCrypto
===========

Simple implementation of common cryptographic algorithms for .NET.

Currently AES(128, 192, 256-Bits), TripleDES(two or three 64-Bits keys), DES and RC2(40 to 128-Bits). More to come soon!!!


Installation
============

You can install the latest package directly to your project in Visual Studio via NuGet Package Manager Console using the command:

```
PM> Install-Package PlainCrypto
```

or searching via the NuGet extension for the package "PlainCrypto".

You can always download or fork this repository and include it in your own solution.


Utilization
===========

+ Create a new instance of the crypto you want to use (CryptoAES, Crypto3DES*, CryptoDES or Crypto RC2) and pass the key(s) in the constructor.

```
ICrypto crypto = new CryptoAES(key);
```

+ Set an initialization vector.**

```
crypto.SetIV(iv)
```

+ Proceed to encrypt or decrypt your string.

```
encryptedMessage = crypto.Encrypt(originalMessage);
```
or
```
decryptedMessage = crypto.Decrypt(encryptedMessage)
```

*Crypto3DES supports two or three key operation with the option to bundle all the keys in a single buffer. 

**Setting an IV is optional for all the cryptos. By default the IV will be generated automatically at instantiation. 


Technical Notes
===============

+ The mode of operation is CBC(Cipher-Block Chainnig).
+ The padding mode is PKCS7.
+ The IV is written/read at/from the beginning of the result.


Dependencies
============

System.Security(.NETFramework, Version=3.5)


License
=======

[MIT](http://opensource.org/licenses/MIT)
