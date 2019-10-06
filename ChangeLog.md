# Revision history for cryptostore

## Next - YYYY-MM-DD

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
