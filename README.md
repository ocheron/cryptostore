# cryptostore

[![Build Status](https://github.com/ocheron/cryptostore/actions/workflows/tests.yml/badge.svg?branch=master)](https://github.com/ocheron/cryptostore/actions/workflows/tests.yml)
[![BSD](https://img.shields.io/badge/License-BSD-blue)](https://en.wikipedia.org/wiki/BSD_licenses)
[![Haskell](https://img.shields.io/badge/Language-Haskell-lightgrey)](https://haskell.org/)

This package allows to read and write cryptographic objects to/from ASN.1.

Currently the following is implemented:

* Reading and writing private keys with optional encryption (this extends
  [x509-store](https://hackage.haskell.org/package/x509-store) API)

* Reading and writing public keys, certificates and CRLs

* PKCS #12 container format (password-based only)

* Many parts of Cryptographic Message Syntax

Please have a look at the examples below as well as some warnings about
cryptographic algorithms.

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

## Public Keys and Signed Objects

Module `Crypto.Store.X509` provides functions to read/write PEM files containing
public keys, X.509 certificates and CRLs.  These files are never encrypted.

Reading a public key and certificate from disk:

```haskell
> :m Data.X509 Crypto.Store.X509
> readPubKeyFile "/path/to/pubkey.pem"
[PubKeyRSA ...]
> readSignedObject "/path/to/cert.pem" :: IO [SignedCertificate]
[SignedExact ...]
```

Writing back to disk:

```haskell
> :m Crypto.Store.X509
> writePubKeyFile "/path/to/pubkey.pem" [pubKey]
> writeSignedObject "/path/to/cert.pem" [cert]
```

## PKCS #12

PKCS #12 is a complex format with multiple layers of protection, providing
usually both privacy and integrity, with a single password for all or not.  The
API to read PKCS #12 files requires some password at each layer.  This API is
available in module `Crypto.Store.PKCS12`.

Reading a binary PKCS #12 file using distinct integrity and privacy passwords:

```haskell
> :set -XOverloadedStrings
> :m Crypto.Store.PKCS12
> Right p12 <- readP12File "/path/to/file.p12"
> let Right pkcs12 = recover "myintegrityassword" p12
> let Right contents = recover "myprivacypassword" (unPKCS12 pkcs12)
> getAllSafeX509Certs contents
[SignedExact {getSigned = ...}]
> recover "myprivacypassword" (getAllSafeKeys contents)
Right [PrivKeyRSA ...]
```

Generating a PKCS #12 file containing a private key:

```haskell
> :set -XOverloadedStrings

-- Generate a private key
> :m Crypto.PubKey.RSA Data.X509
> privKey <- PrivKeyRSA . snd <$> generate (2048 `div` 8) 0x10001

-- Put the key inside a bag
> :m Crypto.Store.PKCS12 Crypto.Store.PKCS8 Crypto.Store.PKCS5 Crypto.Store.CMS
> let attrs = setFriendlyName "Some Key" []
>     keyBag = Bag (KeyBag $ FormattedKey PKCS8Format privKey) attrs
>     contents = SafeContents [keyBag]

-- Encrypt the contents
> salt <- generateSalt 8
> let kdf = PBKDF2 salt 2048 Nothing PBKDF2_SHA256
> encParams <- generateEncryptionParams (CBC AES256)
> let pbes = PBES2 (PBES2Parameter kdf encParams)
>     Right pkcs12 = encrypted pbes "mypassword" contents

-- Save to PKCS #12 with integrity protection (same password)
> salt' <- generateSalt 8
> let iParams = (DigestAlgorithm SHA256, PBEParameter salt' 2048)
> writeP12File "/path/to/privkey.p12" iParams "mypassword" pkcs12
Right ()
```

The API also provides functions to generate/extract a pair containing a private
key and a certificate chain.  This pair is the type alias `Credential` in `tls`.

```haskell
> :set -XOverloadedStrings
> :m Crypto.Store.PKCS12 Crypto.Store.PKCS8 Crypto.Store.PKCS5 Crypto.Store.CMS

-- Read PKCS #12 content as credential
> Right p12 <- readP12File "/path/to/file.p12"
> let Right pkcs12 = recover "myintegrityassword" p12
> let Right (Just cred) = recover "myprivacypassword" (toCredential pkcs12)
> cred
(CertificateChain [...], PrivKeyRSA (...))

-- Scheme to reencrypt the key
> saltK <- generateSalt 8
> let kdfK = PBKDF2 saltK 2048 Nothing PBKDF2_SHA256
> encParamsK <- generateEncryptionParams (CBC AES256)
> let sKey = PBES2 (PBES2Parameter kdfK encParamsK)

-- Scheme to reencrypt the certificate chain
> saltC <- generateSalt 8
> let kdfC = PBKDF2 saltC 1024 Nothing PBKDF2_SHA256
> encParamsC <- generateEncryptionParams (CBC AES128)
> let sCert = PBES2 (PBES2Parameter kdfC encParamsC)

-- Write the content back to a new file
> let Right pkcs12' = fromCredential (Just sCert) sKey "myprivacypassword" cred
> salt <- generateSalt 8
> let iParams = (DigestAlgorithm SHA256, PBEParameter salt 2048)
> writeP12File "/path/to/newfile.p12" iParams "myintegrityassword" pkcs12'
```

Variants `toNamedCredential` and `fromNamedCredential` are also available when
PKCS #12 elements need an alias (friendly name).

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

* streaming
* compressed data
* and S/MIME external format (only PEM is supported, i.e. the textual encoding
  of [RFC 7468](https://tools.ietf.org/html/rfc7468))

### Enveloped data

The following examples generate a CMS structure enveloping some data to a
password recipient, then decrypt the data to recover the content.

#### Generating enveloped data

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

-- Generate the enveloped structure for this single recipient.  Encrypted
-- content is kept attached in the structure.
> Right envelopedData <- envelopData mempty ceKey ceParams [pri] [] info
> let envelopedCI = toAttachedCI envelopedData
> writeCMSFile "/path/to/enveloped.pem" [envelopedCI]
```

#### Opening the enveloped data

```haskell
> :set -XOverloadedStrings
> :m Crypto.Store.CMS

-- Then this recipient just has to read the file and recover enveloped
-- content using the password
> [EnvelopedDataCI envelopedEncapData] <- readCMSFile "/path/to/enveloped.pem"
> envelopedData <- fromAttached envelopedEncapData
> openEnvelopedData (withRecipientPassword "mypassword") envelopedData
Right (DataCI "Hi, what will you need from the cryptostore?")
```

### Signed data

The following examples generate a CMS structure signing data with an RSA key
and certificate, then verify the signature and recover the content.

#### Signing data

```haskell
> :set -XOverloadedStrings
> :m Crypto.Store.CMS Data.X509 Crypto.Store.X509 Crypto.Store.PKCS8

-- Input content info
> let info = DataCI "Some trustworthy content"

-- Read signer certificate and private key
> (key : _) <- readKeyFile "/path/to/privkey.pem" -- assuming single key
> let Right priv = recover "mypassword" key
> chain <- readSignedObject "/path/to/cert.pem" :: IO [SignedCertificate]
> let cert = CertificateChain chain

-- Signature will use RSASSA-PSS and SHA-256
> let sha256 = DigestAlgorithm SHA256
> let params = PSSParams sha256 (MGF1 sha256) 16

-- Generate the signed structure with a single signer.  Signed content is
-- kept attached in the structure.
> let signer = certSigner (RSAPSS params) priv cert (Just []) []
> Right signedData <- signData [signer] info
> let signedCI = toAttachedCI signedData
> writeCMSFile "/path/to/signed.pem" [signedCI]
```

#### Verifying signed data

```haskell
-- Read certificate authorities to be trusted for validation
> :m Crypto.Store.X509 Data.X509.CertificateStore
> store <- makeCertificateStore <$> readSignedObject "/path/to/cacert.pem"

-- Assume we will not verify the signer FQHN.  Instead the certificate could be
-- related to an identity from which we received the signed data.
> :m Data.Default.Class Data.X509 Data.X509.Validation
> let validateNoFQHN = validate HashSHA256 def def { checkFQHN = False }
> let noServiceID = (undefined, undefined)

-- Read the signed data and validate it to recover the content
> :m Crypto.Store.CMS Data.Default.Class
> [SignedDataCI signedEncapData] <- readCMSFile "/path/to/signed.pem"
> signedData <- fromAttached signedEncapData
> let doValidation _ chain = null <$> validateNoFQHN store def noServiceID chain
> verifySignedData (withSignerCertificate doValidation) signedData
Right (DataCI "Some trustworthy content")
```

## Algorithms and security

For compatibility reasons cryptostore implements many outdated algorithms that
are still in use in data formats.  Please check your security requirements.  New
applications should favor PBKDF2 or Scrypt and AEAD ciphers.

Additionally, the package is designed exclusively for store and forward
scenarios, as most algorithms will not be perfectly safe for interactive use.
ECDSA signature generation uses the generic ECC implementation from cryptonite
and could leak the private key under timing attack.  A padding oracle on
CBC-encrypted ciphertext allows to recover the plaintext.

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
