# Revision history for cryptostore

## Next - YYYY-MM-DD

* Added functions `toNamedCredential` and `fromNamedCredential` to handle
  PKCS#12 elements with an alias (friendly name).

* Functions `fromCredential` and `fromNamedCredential` now generate PKCS#12
  elements with the `localKeyId` attribute.

* Function `toCredential` is now able to locate the leaf certificate and issuers
  more reliably.

## 0.1.0.0 -- 2018-09-23

* First version. Released on an unsuspecting world.
