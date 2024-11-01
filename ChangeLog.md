# Revision history for cryptostore

## Unreleased

* Added support of PBMAC1 for PKCS#12 integrity.  Type `IntegrityParams` used
  in functions `writeP12File` and `writeP12FileToMemory` is modified.
  A low-level function for PBMAC1 is also available in the PKCS5 module.

* CMS now supports SHA-3 algorithms in HMAC, or as digest algorithm

* Functions `pemToKey`, `pemToPubKey` and `pemToContentInfo` are modified to
  return error details when a PEM object cannot be read.  The old API signature
  that discarded error details is available with functions renamed
  `pemToKeyAccum`, `pemToPubKeyAccum` and `pemToContentInfoAccum`.

* Fixed encoding of some HMAC and PRF parameters

## 0.3.1.0 - 2024-05-05

* Strict validation of GCM/CCM authentication tag length

## 0.3.0.1 - 2023-06-25

* Add optional flag to use crypton instead of cryptonite

## 0.3.0.0 - 2023-01-14

* API change in PKCS5, PKCS8 and PKCS12 modules to handle better password-based
  encryption derived from an empty password.  All encryption/decryption
  functions now expect an opaque `ProtectionPassword` data type.  Conversion
  functions `toProtectionPassword` and `fromProtectionPassword` are provided.
  Additionnally in the PKCS12 module, the type `OptProtected` is replaced with
  `OptAuthenticated` when dealing with password integrity.  Similarly at that
  level, function `recover` is to be replaced with `recoverAuthenticated`.

* Added support for KMAC (Keccak Message Authentication Code) in CMS
  authenticated data, through constructors `KMAC_SHAKE128` and `KMAC_SHAKE256`.

* CMS key agreement now supports derivation with HKDF along with X9.63.  Data
  type `KeyAgreementParams` is modified to include a KDF instead of simply the
  digest algorithm.  HKDF has assigned OIDs only for standard DH and cannot be
  used with cofactor DH.

* Added CMS utility functions to deal with the `signingTime` attribute.

* Changed `withSignerCertificate` validation callback API to include the
  `signingTime` value when available.

## 0.2.3.0 - 2022-11-05

* Fix RC2 on big-endian architectures

## 0.2.2.0 - 2022-04-16

* Fix buffer overrun in `pkcs12Derive`

## 0.2.1.0 - 2019-10-13

* Added CMS fuctions `contentInfoToDER` and `berToContentInfo` in order to
  generate and parse raw ASN.1.

* Implementation of AES key wrap had some optimizations.

* SHAKE hash algorithms now allow arbitrary output lengths.  Lengths that are
  very small decrease security.  A protection is added so that attempts to use
  lengths which are too small fail, although the criteria are conservative.
  Generating and parsing content has no restriction.

## 0.2.0.0 - 2019-03-24

* Added functions `toNamedCredential` and `fromNamedCredential` to handle
  PKCS#12 elements with an alias (friendly name).

* Functions `fromCredential` and `fromNamedCredential` now generate PKCS#12
  elements with the `localKeyId` attribute.

* Function `toCredential` is now able to locate the leaf certificate and issuers
  more reliably.

* Algorithms X25519, X448, Ed25519 and Ed448 are now supported.

* CMS functions `digestVerify` and `verifySignedData` now return an `Either`
  instead of a `Maybe`.  Errors `DigestMismatch` and `SignatureNotVerified` are
  added to report failures.

* CMS types `SignedData`, `DigestedData` and `AuthenticatedData` now retain the
  encapsulated content in encoded form (with type alias `EncapsulatedContent`)
  instead of a decoded and parsed `ContentInfo`.  The `ContentInfo` is parsed
  and provided only when successfully unwrapping the encapsulated type.

* The CMS interface is transformed to support detached content.  CMS types now
  have a type parameter to distinguish between a direct reference to the
  encapsulated or encrypted content, and the `Encap` indirection which denotes
  an attached or detached content.  Functions building CMS types do not return
  the `ContentInfo` directly anymore, but an intermediate type to be fed into
  `toAttachedCI` or `toDetachedCI`.  Reverse transformation is possible with
  utility functions `fromAttached` and `fromDetached` when unwrapping a
  `ContentInfo`.

## 0.1.0.0 - 2018-09-23

* First version. Released on an unsuspecting world.
