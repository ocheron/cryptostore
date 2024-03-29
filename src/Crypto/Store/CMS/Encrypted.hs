-- |
-- Module      : Crypto.Store.CMS.Encrypted
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
--
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Store.CMS.Encrypted
    ( EncryptedContent
    , ContentEncryptionKey
    , EncryptedData(..)
    , encryptedContentInfoASN1S
    , parseEncryptedContentInfo
    ) where

import Control.Applicative
import Control.Monad

import           Data.ASN1.Types
import qualified Data.ByteString as B

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Attribute
import Crypto.Store.CMS.Type
import Crypto.Store.CMS.Util

-- | Key used for content encryption.
type ContentEncryptionKey = B.ByteString

-- | Encrypted content.
type EncryptedContent = B.ByteString

-- | Encrypted content information.
data EncryptedData content = EncryptedData
    { edContentType :: ContentType
      -- ^ Inner content type
    , edContentEncryptionParams :: ContentEncryptionParams
      -- ^ Encryption algorithm
    , edEncryptedContent :: content
      -- ^ Encrypted content info
    , edUnprotectedAttrs :: [Attribute]
      -- ^ Optional unprotected attributes
    }
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e (EncryptedData (Encap EncryptedContent)) where
    asn1s EncryptedData{..} =
        asn1Container Sequence (ver . eci . ua)
      where
        ver = gIntVal (if null edUnprotectedAttrs then 0 else 2)
        eci = encryptedContentInfoASN1S
                  (edContentType, edContentEncryptionParams, edEncryptedContent)
        ua  = attributesASN1S (Container Context 1) edUnprotectedAttrs

instance Monoid e => ParseASN1Object e (EncryptedData (Encap EncryptedContent)) where
    parse =
        onNextContainer Sequence $ do
            IntVal v <- getNext
            when (v /= 0 && v /= 2) $
                throwParseError ("EncryptedData: parsed invalid version: " ++ show v)
            (ct, params, ec) <- parseEncryptedContentInfo
            attrs <- parseAttributes (Container Context 1)
            return EncryptedData { edContentType = ct
                                 , edContentEncryptionParams = params
                                 , edEncryptedContent = ec
                                 , edUnprotectedAttrs = attrs
                                 }

-- | Generate ASN.1 for EncryptedContentInfo.
encryptedContentInfoASN1S :: (ASN1Elem e, ProduceASN1Object e alg)
                          => (ContentType, alg, Encap EncryptedContent) -> ASN1Stream e
encryptedContentInfoASN1S (ct, alg, ec) =
    asn1Container Sequence (ct' . alg' . ec')
  where
    ct'  = gOID (getObjectID ct)
    alg' = asn1s alg
    ec'  = encapsulatedASN1S (Container Context 0) ec

encapsulatedASN1S :: ASN1Elem e
                  => ASN1ConstructionType -> Encap EncryptedContent -> ASN1Stream e
encapsulatedASN1S _   Detached     = id
encapsulatedASN1S ty (Attached bs) = asn1Container ty (gOctetString bs)

-- | Parse EncryptedContentInfo from ASN.1.
parseEncryptedContentInfo :: ParseASN1Object e alg
                          => ParseASN1 e (ContentType, alg, Encap EncryptedContent)
parseEncryptedContentInfo = onNextContainer Sequence $ do
    OID oid <- getNext
    alg <- parse
    b <- hasNext
    ec <- if b then Attached <$> parseEncryptedContent else return Detached
    withObjectID "content type" oid $ \ct -> return (ct, alg, ec)
  where
    parseEncryptedContent = parseWrapped <|> parsePrimitive
    parseWrapped  = onNextContainer (Container Context 0) parseOctetStrings
    parsePrimitive = do Other Context 0 bs <- getNext; return bs
