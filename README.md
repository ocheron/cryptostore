# cryptostore

[![Build Status](https://travis-ci.org/ocheron/cryptostore.png?branch=master)](https://travis-ci.org/ocheron/cryptostore)
[![BSD](https://b.repl.ca/v1/license-BSD-blue.png)](https://en.wikipedia.org/wiki/BSD_licenses)
[![Haskell](https://b.repl.ca/v1/language-haskell-lightgrey.png)](https://haskell.org/)

This package allows to read and write cryptographic objects to/from ASN.1.

Currently the following is implemented:

* Reading and writing private keys with optional encryption (this extends
  [x509-store](https://hackage.haskell.org/package/x509-store) API)

* Many parts of Cryptographic Message Syntax

## Private Keys

The API to read and write private keys is available in module
`Crypto.Store.PKCS8`.  When encrypting, some types and functions from module
`Crypto.Store.PKCS5` are also necessary.

Reading a private key from disk:

```haskell
> :set -XOverloadedStrings
> :m Crypto.Store.PKCS8
> (key : _) <- readKeyFile "/path/to/privkey.pem" -- assuming single key
> recover "mypassword" key
Right (PrivKeyRSA ...)
```

Generating a private key and writing to disk, without encryption:

```haskell
> :m Crypto.PubKey.RSA Crypto.Store.PKCS8 Data.X509
> privKey <- PrivKeyRSA . snd <$> generate (2048 `div` 8) 0x10001
> writeKeyFile PKCS8Format "/path/to/privkey.pem" [privKey]
```

Generating a private key and writing to disk, with password-based encryption:

```haskell
> :set -XOverloadedStrings
> :m Crypto.PubKey.RSA Crypto.Store.PKCS8 Data.X509 Crypto.Store.PKCS5
> privKey <- PrivKeyRSA . snd <$> generate (2048 `div` 8) 0x10001
> salt <- generateSalt 8
> let kdf = PBKDF2 salt 2048 Nothing PBKDF2_SHA256
> encParams <- generateEncryptionParams (CBC AES256)
> let pbes = PBES2 (PBES2Parameter kdf encParams)
> writeEncryptedKeyFile "/path/to/privkey.pem" pbes "mypassword" privKey
Right ()
```

Parameters used in this example are AES-256-CBC as cipher, PBKDF2 as
key-derivation function, with an 8-byte salt, 2048 iterations and SHA-256 as
pseudorandom function.

## Cryptographic Message Syntax

The API to read and write CMS content is available in `Crypto.Store.CMS`.  The
main data type `ContentInfo` represents a CMS structure.

Implemented content types are:

* data
* signed data
* enveloped data
* digested data
* encrypted data
* authenticated data
* and authenticated-enveloped data

Notable omissions:

* detached content
* streaming
* compressed data
* and S/MIME external format (only PEM is supported, i.e. the textual encoding
  of [RFC 7468](https://tools.ietf.org/html/rfc7468))

The following examples generate a CMS structure enveloping some data to a
password recipient, then decrypt the data to recover the content.

### Generating enveloped data

```haskell
> :set -XOverloadedStrings
> :m Crypto.Store.CMS

-- Input content info
> let info = DataCI "Hi, what will you need from the cryptostore?"

-- Content encryption will use AES-128-CBC
> ceParams <- generateEncryptionParams (CBC AES128)
> ceKey <- generateKey ceParams :: IO ContentEncryptionKey

-- Encrypt the Content Encryption Key with a Password Recipient Info,
-- i.e. a KDF will derive the Key Encryption Key from a password
-- that the recipient will need to know
> salt <- generateSalt 8
> let kdf = PBKDF2 salt 2048 Nothing PBKDF2_SHA256
> keParams <- generateEncryptionParams (CBC AES128)
> let pri = forPasswordRecipient "mypassword" kdf (PWRIKEK keParams)

-- Generate the enveloped structure for this single recipient
> Right envelopedCI <- envelopData mempty ceKey ceParams [pri] [] info
> writeCMSFile "/path/to/enveloped.pem" [envelopedCI]
```

### Opening the enveloped data

```haskell
> :set -XOverloadedStrings
> :m Crypto.Store.CMS

-- Then this recipient just has to read the file and recover enveloped
-- content using the password
> [EnvelopedDataCI envelopedData] <- readCMSFile "/path/to/enveloped.pem"
> openEnvelopedData (withRecipientPassword "mypassword") envelopedData
Right (DataCI "Hi, what will you need from the cryptostore?")
```

## Design

Main dependencies are:

* [cryptonite](https://hackage.haskell.org/package/cryptonite) implementation of
  public-key systems, symmetric ciphers, KDFs, MAC, and one-way hash functions
* [asn1-types](https://hackage.haskell.org/package/asn1-types) and
  [asn1-encoding](https://hackage.haskell.org/package/asn1-encoding) to encode
  and decode ASN.1 content
* [pem](https://hackage.haskell.org/package/pem) to read and write PEM files
* [x509](https://hackage.haskell.org/package/x509) contains the certificate and
  private-key data types

Internally the ASN.1 parser used is a local implementation extending the code of
[asn1-parse](https://hackage.haskell.org/package/asn1-parse).  This extension is
able to parse `ASN1Repr`, i.e. a stream of ASN.1 tags associated with the binary
decoding events the tags were originated from.  Similarly generation of ASN.1
content does not use the `ASN1S` type but an extension which is able to encode a
stream where some parts have already been encoded.  Retaining the original
BER/DER encoding is required when incorporating MACed or signed content.
