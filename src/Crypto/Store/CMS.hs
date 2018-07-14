-- |
-- Module      : Crypto.Store.CMS
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Cryptographic Message Syntax
--
-- * <https://tools.ietf.org/html/rfc5652 RFC 5652>: Cryptographic Message Syntax (CMS)
-- * <https://tools.ietf.org/html/rfc3370 RFC 3370>: Cryptographic Message Syntax (CMS) Algorithms
-- * <https://tools.ietf.org/html/rfc5754 RFC 5754>: Using SHA2 Algorithms with Cryptographic Message Syntax
-- * <https://tools.ietf.org/html/rfc3211 RFC 3211>: Password-based Encryption for CMS
--
-- /TODO: only symmetric crypto is implemented currently/
{-# LANGUAGE RecordWildCards #-}
module Crypto.Store.CMS
    ( ContentType(..)
    , ContentInfo(..)
    , getContentType
    -- * Reading and writing PEM files
    , module Crypto.Store.CMS.PEM
    -- * Enveloped data
    , EncryptedKey
    , KeyEncryptionParams(..)
    , RecipientInfo(..)
    , EnvelopedData(..)
    , ProducerOfRI
    , ConsumerOfRI
    , envelopData
    , openEnvelopedData
    -- ** Key Encryption Key recipients
    , KEKRecipientInfo(..)
    , KEKIdentifier(..)
    , OtherKeyAttribute(..)
    , KeyEncryptionKey
    , forKeyRecipient
    , withRecipientKey
     -- ** Password recipients
   , PasswordRecipientInfo(..)
    , forPasswordRecipient
    , withRecipientPassword
    -- * Digested data
    , DigestAlgorithm(..)
    , DigestType(..)
    , DigestedData(..)
    , digestData
    , digestVerify
    -- * Encrypted data
    , ContentEncryptionKey
    , ContentEncryptionCipher(..)
    , ContentEncryptionAlg(..)
    , ContentEncryptionParams
    , EncryptedContent
    , EncryptedData(..)
    , generateEncryptionParams
    , getContentEncryptionAlg
    , encryptData
    , decryptData
    -- * Message authentication
    , MessageAuthenticationCode
    , MACAlgorithm(..)
    -- * Key derivation
    , Salt
    , generateSalt
    , KeyDerivationFunc(..)
    , PBKDF2_PRF(..)
    -- * Secret-key algorithms
    , HasKeySize(..)
    , generateKey
    -- * CMS attributes
    , Attribute(..)
    , findAttribute
    , setAttribute
    , filterAttributes
    ) where

import Data.List.NonEmpty (nonEmpty)
import Data.Semigroup

import Crypto.Hash

import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Attribute
import Crypto.Store.CMS.Encrypted
import Crypto.Store.CMS.Enveloped
import Crypto.Store.CMS.Info
import Crypto.Store.CMS.PEM
import Crypto.Store.CMS.Type


-- DigestedData

-- | Add a digested-data layer on the specified content info.
digestData :: DigestType -> ContentInfo -> ContentInfo
digestData (DigestType alg) ci = DigestedDataCI dd
  where dd = DigestedData
                 { ddDigestAlgorithm = alg
                 , ddContentInfo     = ci
                 , ddDigest          = hash (encapsulate ci)
                 }

-- | Return the inner content info but only if the digest is valid.
digestVerify :: DigestedData -> Maybe ContentInfo
digestVerify DigestedData{..} =
    if ddDigest == hash (encapsulate ddContentInfo)
        then Just ddContentInfo
        else Nothing


-- EncryptedData

-- | Add an encrypted-data layer on the specified content info.  The content is
-- encrypted with specified key and algorithm.
--
-- Some optional attributes can be added but will not be encrypted.
encryptData :: ContentEncryptionKey
            -> ContentEncryptionParams
            -> [Attribute]
            -> ContentInfo
            -> Either String ContentInfo
encryptData key params attrs ci =
    EncryptedDataCI . build <$> contentEncrypt key params (encapsulate ci)
  where
    build ec = EncryptedData
                   { edContentType = getContentType ci
                   , edContentEncryptionParams = params
                   , edEncryptedContent = ec
                   , edUnprotectedAttrs = attrs
                   }

-- | Decrypt an encrypted content info using the specified key.
decryptData :: ContentEncryptionKey
            -> EncryptedData
            -> Either String ContentInfo
decryptData key EncryptedData{..} = do
    decrypted <- contentDecrypt key edContentEncryptionParams edEncryptedContent
    decapsulate edContentType decrypted


-- EnvelopedData

-- | Add an enveloped-data layer on the specified content info.  The content is
-- encrypted with specified key and algorithm.  The key is then processed by
-- one or several 'ProducerOfRI' functions to create recipient info elements.
--
-- Some optional attributes can be added but will not be encrypted.
envelopData :: Applicative f
            => ContentEncryptionKey
            -> ContentEncryptionParams
            -> [ProducerOfRI f]
            -> [Attribute]
            -> ContentInfo
            -> f (Either String ContentInfo)
envelopData key params envFns attrs ci =
    f <$> (sequence <$> traverse ($ key) envFns)
  where
    ebs = contentEncrypt key params (encapsulate ci)
    f ris = EnvelopedDataCI <$> (build <$> ebs <*> ris)
    build bs ris = EnvelopedData
                       { evRecipientInfos = ris
                       , evContentType = getContentType ci
                       , evContentEncryptionParams = params
                       , evEncryptedContent = bs
                       , evUnprotectedAttrs = attrs
                       }

-- | Recover an enveloped content info using the specified 'ConsumerOfRI'
-- function.
openEnvelopedData :: ConsumerOfRI -> EnvelopedData -> Either String ContentInfo
openEnvelopedData devFn EnvelopedData{..} =
    riAttempts (map devFn evRecipientInfos) >>= unwrap
  where
    ct       = evContentType
    params   = evContentEncryptionParams
    unwrap k = contentDecrypt k params evEncryptedContent >>= decapsulate ct


-- Utilities

riAttempts :: [Either String b] -> Either String b
riAttempts list =
    case nonEmpty list of
        Just ne -> sconcat ne <> Left "No recipient info matched"
        Nothing -> Left "No recipient info found"
