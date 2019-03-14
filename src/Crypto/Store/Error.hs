-- |
-- Module      : Crypto.Store.Error
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Error data type.
module Crypto.Store.Error
    ( StoreError(..)
    , fromCryptoFailable
    ) where

import Crypto.Error
import Crypto.PubKey.RSA.Types as RSA

import Data.ASN1.Error

-- | Error type in cryptostore.
data StoreError =
      CryptoError CryptoError
      -- ^ Wraps a cryptonite error
    | RSAError RSA.Error
      -- ^ Wraps an RSA crypto error
    | DecodingError ASN1Error
      -- ^ Error while decoding ASN.1 content
    | ParseFailure String
      -- ^ Error while parsing an ASN.1 object
    | DecryptionFailed
      -- ^ Unable to decrypt, incorrect key or password?
    | BadContentMAC
      -- ^ MAC verification failed, incorrect key or password?
    | BadChecksum
      -- ^ Checksum verification failed, incorrect key or password?
    | DigestMismatch
      -- ^ Digest verification failed
    | SignatureNotVerified
      -- ^ Signature verification failed
    | InvalidInput String
      -- ^ Some condition is not met about input to algorithm
    | InvalidPassword String
      -- ^ Some condition is not met about input password
    | InvalidParameter String
      -- ^ Some condition is not met about algorithm parameters
    | UnexpectedPublicKeyType
      -- ^ The algorithm expects another public key type
    | UnexpectedPrivateKeyType
      -- ^ The algorithm expects another private key type
    | RecipientTypeMismatch
      -- ^ Returned when the type of recipient info does not match the consumer
      -- function
    | RecipientKeyNotFound
      -- ^ The certificate provided does not match any encrypted key found
    | NoRecipientInfoFound
      -- ^ No recipient info is available in the enveloped data
    | NoRecipientInfoMatched
      -- ^ No recipient info could be used with the consumer function
    | UnsupportedOriginatorFormat
      -- ^ Only anonymous public key is supported
    | UnsupportedEllipticCurve
      -- ^ The elliptic curve used is not supported
    | NamedCurveRequired
      -- ^ The algorithm requires a named elliptic curve
    deriving (Show,Eq)

-- | Turn a 'CryptoFailed' into a 'StoreError'.
fromCryptoFailable ::CryptoFailable a -> Either StoreError a
fromCryptoFailable (CryptoPassed a) = Right a
fromCryptoFailable (CryptoFailed e) = Left (CryptoError e)
