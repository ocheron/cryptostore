-- |
-- Module      : Data.Store.PKCS5
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Password-Based Cryptography, aka PKCS #5.
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.Store.PKCS5
    ( Password
    , EncryptedContent
    -- * High-level API
    , PKCS5(..)
    , encrypt
    , decrypt
    -- * Encryption schemes
    , EncryptionScheme(..)
    , PBEParameter(..)
    , PBES2Parameter(..)
    -- * Key derivation
    , KeyDerivationFunc(..)
    , PBKDF2_PRF(..)
    , Salt
    , generateSalt
    -- * Content encryption
    , ContentEncryptionParams
    , ContentEncryptionAlg(..)
    , ContentEncryptionCipher(..)
    , generateEncryptionParams
    , getContentEncryptionAlg
    -- * Low-level API
    , pbEncrypt
    , pbDecrypt
    ) where

import           Data.ASN1.Types
import           Data.ByteArray (ByteArrayAccess)
import           Data.ByteString (ByteString)
import           Data.Maybe (fromMaybe)

import Crypto.Store.ASN1.Parse
import Crypto.Store.ASN1.Generate
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Encrypted
import Crypto.Store.CMS.Enveloped
import Crypto.Store.CMS.Util
import Crypto.Store.Error
import Crypto.Store.PKCS5.PBES1

data EncryptionSchemeType = Type_PBES2
                          | Type_PBE_MD5_DES_CBC
                          | Type_PBE_SHA1_DES_CBC
                          | Type_PBE_SHA1_RC4_128
                          | Type_PBE_SHA1_RC4_40
                          | Type_PBE_SHA1_DES_EDE3_CBC
                          | Type_PBE_SHA1_DES_EDE2_CBC
                          | Type_PBE_SHA1_RC2_128
                          | Type_PBE_SHA1_RC2_40

instance Enumerable EncryptionSchemeType where
    values = [ Type_PBES2
             , Type_PBE_MD5_DES_CBC
             , Type_PBE_SHA1_DES_CBC
             , Type_PBE_SHA1_RC4_128
             , Type_PBE_SHA1_RC4_40
             , Type_PBE_SHA1_DES_EDE3_CBC
             , Type_PBE_SHA1_DES_EDE2_CBC
             , Type_PBE_SHA1_RC2_128
             , Type_PBE_SHA1_RC2_40
             ]

instance OIDable EncryptionSchemeType where
    getObjectID Type_PBES2                 = [1,2,840,113549,1,5,13]
    getObjectID Type_PBE_MD5_DES_CBC       = [1,2,840,113549,1,5,3]
    getObjectID Type_PBE_SHA1_DES_CBC      = [1,2,840,113549,1,5,10]
    getObjectID Type_PBE_SHA1_RC4_128      = [1,2,840,113549,1,12,1,1]
    getObjectID Type_PBE_SHA1_RC4_40       = [1,2,840,113549,1,12,1,2]
    getObjectID Type_PBE_SHA1_DES_EDE3_CBC = [1,2,840,113549,1,12,1,3]
    getObjectID Type_PBE_SHA1_DES_EDE2_CBC = [1,2,840,113549,1,12,1,4]
    getObjectID Type_PBE_SHA1_RC2_128      = [1,2,840,113549,1,12,1,5]
    getObjectID Type_PBE_SHA1_RC2_40       = [1,2,840,113549,1,12,1,6]

instance OIDNameable EncryptionSchemeType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

-- | Password-Based Encryption Scheme (PBES).
data EncryptionScheme = PBES2 PBES2Parameter               -- ^ PBES2
                      | PBE_MD5_DES_CBC PBEParameter       -- ^ pbeWithMD5AndDES-CBC
                      | PBE_SHA1_DES_CBC PBEParameter      -- ^ pbeWithSHA1AndDES-CBC
                      | PBE_SHA1_RC4_128 PBEParameter      -- ^ pbeWithSHAAnd128BitRC4
                      | PBE_SHA1_RC4_40 PBEParameter       -- ^ pbeWithSHAAnd40BitRC4
                      | PBE_SHA1_DES_EDE3_CBC PBEParameter -- ^ pbeWithSHAAnd3-KeyTripleDES-CBC
                      | PBE_SHA1_DES_EDE2_CBC PBEParameter -- ^ pbeWithSHAAnd2-KeyTripleDES-CBC
                      | PBE_SHA1_RC2_128 PBEParameter      -- ^ pbeWithSHAAnd128BitRC2-CBC
                      | PBE_SHA1_RC2_40 PBEParameter       -- ^ pbewithSHAAnd40BitRC2-CBC
                      deriving (Show,Eq)

-- | PBES2 parameters.
data PBES2Parameter = PBES2Parameter
    { pbes2KDF     :: KeyDerivationFunc       -- ^ Key derivation function
    , pbes2EScheme :: ContentEncryptionParams -- ^ Underlying encryption scheme
    }
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e PBES2Parameter where
    asn1s PBES2Parameter{..} =
        let kdFunc  = algorithmASN1S Sequence pbes2KDF
            eScheme = asn1s pbes2EScheme
         in asn1Container Sequence (kdFunc . eScheme)

instance Monoid e => ParseASN1Object e PBES2Parameter where
    parse = onNextContainer Sequence $ do
        kdFunc  <- parseAlgorithm Sequence
        eScheme <- parse
        case kdfKeyLength kdFunc of
            Nothing -> return ()
            Just sz
                | validateKeySize eScheme sz -> return ()
                | otherwise -> throwParseError "PBES2Parameter: parsed key length incompatible with encryption scheme"
        return PBES2Parameter { pbes2KDF = kdFunc, pbes2EScheme = eScheme }

instance AlgorithmId EncryptionScheme where
    type AlgorithmType EncryptionScheme = EncryptionSchemeType
    algorithmName _  = "encryption scheme"

    algorithmType (PBES2 _)                 = Type_PBES2
    algorithmType (PBE_MD5_DES_CBC _)       = Type_PBE_MD5_DES_CBC
    algorithmType (PBE_SHA1_DES_CBC _)      = Type_PBE_SHA1_DES_CBC
    algorithmType (PBE_SHA1_RC4_128 _)      = Type_PBE_SHA1_RC4_128
    algorithmType (PBE_SHA1_RC4_40 _)       = Type_PBE_SHA1_RC4_40
    algorithmType (PBE_SHA1_DES_EDE3_CBC _) = Type_PBE_SHA1_DES_EDE3_CBC
    algorithmType (PBE_SHA1_DES_EDE2_CBC _) = Type_PBE_SHA1_DES_EDE2_CBC
    algorithmType (PBE_SHA1_RC2_128 _)      = Type_PBE_SHA1_RC2_128
    algorithmType (PBE_SHA1_RC2_40 _)       = Type_PBE_SHA1_RC2_40

    parameterASN1S (PBES2 p)                 = asn1s p
    parameterASN1S (PBE_MD5_DES_CBC p)       = asn1s p
    parameterASN1S (PBE_SHA1_DES_CBC p)      = asn1s p
    parameterASN1S (PBE_SHA1_RC4_128 p)      = asn1s p
    parameterASN1S (PBE_SHA1_RC4_40 p)       = asn1s p
    parameterASN1S (PBE_SHA1_DES_EDE3_CBC p) = asn1s p
    parameterASN1S (PBE_SHA1_DES_EDE2_CBC p) = asn1s p
    parameterASN1S (PBE_SHA1_RC2_128 p)      = asn1s p
    parameterASN1S (PBE_SHA1_RC2_40 p)       = asn1s p

    parseParameter Type_PBES2                 = PBES2 <$> parse
    parseParameter Type_PBE_MD5_DES_CBC       = PBE_MD5_DES_CBC <$> parse
    parseParameter Type_PBE_SHA1_DES_CBC      = PBE_SHA1_DES_CBC <$> parse
    parseParameter Type_PBE_SHA1_RC4_128      = PBE_SHA1_RC4_128 <$> parse
    parseParameter Type_PBE_SHA1_RC4_40       = PBE_SHA1_RC4_40 <$> parse
    parseParameter Type_PBE_SHA1_DES_EDE3_CBC = PBE_SHA1_DES_EDE3_CBC <$> parse
    parseParameter Type_PBE_SHA1_DES_EDE2_CBC = PBE_SHA1_DES_EDE2_CBC <$> parse
    parseParameter Type_PBE_SHA1_RC2_128      = PBE_SHA1_RC2_128 <$> parse
    parseParameter Type_PBE_SHA1_RC2_40       = PBE_SHA1_RC2_40 <$> parse

instance ASN1Elem e => ProduceASN1Object e EncryptionScheme where
    asn1s = algorithmASN1S Sequence

instance Monoid e => ParseASN1Object e EncryptionScheme where
    parse = parseAlgorithm Sequence


-- High-level API

-- | Content encrypted with a Password-Based Encryption Scheme (PBES).
--
-- The content will usually be the binary representation of an ASN.1 object,
-- however the transformation may be applied to any bytestring.
data PKCS5 = PKCS5
    { encryptionAlgorithm :: EncryptionScheme -- ^ Scheme used to encrypt content
    , encryptedData       :: EncryptedContent -- ^ Encrypted content
    }
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e PKCS5 where
    asn1s PKCS5{..} = asn1Container Sequence (alg . bs)
      where alg = asn1s encryptionAlgorithm
            bs  = gOctetString encryptedData

instance Monoid e => ParseASN1Object e PKCS5 where
    parse = onNextContainer Sequence $ do
        alg <- parse
        OctetString bs <- getNext
        return PKCS5 { encryptionAlgorithm = alg, encryptedData = bs }

instance ASN1Object PKCS5 where
    toASN1   = asn1s
    fromASN1 = runParseASN1State parse

-- | Encrypt a bytestring with the specified encryption scheme and password.
encrypt :: EncryptionScheme -> Password -> ByteString -> Either StoreError PKCS5
encrypt alg pwd bs = build <$> pbEncrypt alg bs pwd
  where
    build ed = ed `seq` PKCS5 { encryptionAlgorithm = alg, encryptedData = ed }

-- | Decrypt the PKCS #5 content with the specified password.
decrypt :: PKCS5 -> Password -> Either StoreError ByteString
decrypt obj = pbDecrypt (encryptionAlgorithm obj) (encryptedData obj)


-- Encryption Schemes

-- | Encrypt a bytestring with the specified encryption scheme and password.
pbEncrypt :: EncryptionScheme -> ByteString -> Password
          -> Either StoreError EncryptedContent
pbEncrypt (PBES2 p)                 = pbes2  contentEncrypt p
pbEncrypt (PBE_MD5_DES_CBC p)       = pkcs5  Left contentEncrypt MD5  DES p
pbEncrypt (PBE_SHA1_DES_CBC p)      = pkcs5  Left contentEncrypt SHA1 DES p
pbEncrypt (PBE_SHA1_RC4_128 p)      = pkcs12stream Left rc4Combine SHA1 16 p
pbEncrypt (PBE_SHA1_RC4_40 p)       = pkcs12stream Left rc4Combine SHA1 5 p
pbEncrypt (PBE_SHA1_DES_EDE3_CBC p) = pkcs12 Left contentEncrypt SHA1 DES_EDE3 p
pbEncrypt (PBE_SHA1_DES_EDE2_CBC p) = pkcs12 Left contentEncrypt SHA1 DES_EDE2 p
pbEncrypt (PBE_SHA1_RC2_128 p)      = pkcs12rc2 Left contentEncrypt SHA1 128 p
pbEncrypt (PBE_SHA1_RC2_40 p)       = pkcs12rc2 Left contentEncrypt SHA1 40 p

-- | Decrypt an encrypted bytestring with the specified encryption scheme and
-- password.
pbDecrypt :: EncryptionScheme -> EncryptedContent -> Password -> Either StoreError ByteString
pbDecrypt (PBES2 p)                 = pbes2  contentDecrypt p
pbDecrypt (PBE_MD5_DES_CBC p)       = pkcs5  Left contentDecrypt MD5  DES p
pbDecrypt (PBE_SHA1_DES_CBC p)      = pkcs5  Left contentDecrypt SHA1 DES p
pbDecrypt (PBE_SHA1_RC4_128 p)      = pkcs12stream Left rc4Combine SHA1 16 p
pbDecrypt (PBE_SHA1_RC4_40 p)       = pkcs12stream Left rc4Combine SHA1 5 p
pbDecrypt (PBE_SHA1_DES_EDE3_CBC p) = pkcs12 Left contentDecrypt SHA1 DES_EDE3 p
pbDecrypt (PBE_SHA1_DES_EDE2_CBC p) = pkcs12 Left contentDecrypt SHA1 DES_EDE2 p
pbDecrypt (PBE_SHA1_RC2_128 p)      = pkcs12rc2 Left contentDecrypt SHA1 128 p
pbDecrypt (PBE_SHA1_RC2_40 p)       = pkcs12rc2 Left contentDecrypt SHA1 40 p

pbes2 :: ByteArrayAccess password
      => (Key -> ContentEncryptionParams -> ByteString -> result)
      -> PBES2Parameter -> ByteString -> password -> result
pbes2 encdec PBES2Parameter{..} bs pwd = encdec key pbes2EScheme bs
  where key = kdfDerive pbes2KDF len pwd :: Key
        len = fromMaybe (getMaximumKeySize pbes2EScheme) (kdfKeyLength pbes2KDF)
