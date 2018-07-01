-- |
-- Module      : Crypto.Store.CMS.Encrypted
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
--
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
data EncryptedData = EncryptedData
    { edContentType :: ContentType
      -- ^ Inner content type
    , edContentEncryptionParams :: ContentEncryptionParams
      -- ^ Encryption algorithm
    , edEncryptedContent :: EncryptedContent
      -- ^ Encrypted content info
    , edUnprotectedAttrs :: [Attribute]
      -- ^ Optional unprotected attributes
    }
    deriving (Show,Eq)

instance ParseASN1Object EncryptedData where
    asn1s EncryptedData{..} =
        asn1Container Sequence (ver . eci . ua)
      where
        ver = gIntVal (if null edUnprotectedAttrs then 0 else 2)
        eci = encryptedContentInfoASN1S
                  (edContentType, edContentEncryptionParams, edEncryptedContent)
        ua  = attributesASN1S (Container Context 1) edUnprotectedAttrs

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
encryptedContentInfoASN1S :: ParseASN1Object alg
                          => (ContentType, alg, B.ByteString) -> ASN1S
encryptedContentInfoASN1S (ct, alg, ec) =
    asn1Container Sequence (ct' . alg' . ec')
  where
    ct'  = gOID (getObjectID ct)
    alg' = asn1s alg
    ec'  = asn1Container (Container Context 0) (gOctetString ec)

-- | Parse EncryptedContentInfo from ASN.1.
parseEncryptedContentInfo :: ParseASN1Object alg
                          => ParseASN1 (ContentType, alg, B.ByteString)
parseEncryptedContentInfo = onNextContainer Sequence $ do
    OID oid <- getNext
    alg <- parse
    ec <- parseEncryptedContent
    withObjectID "content type" oid $ \ct -> return (ct, alg, ec)
  where
    parseEncryptedContent = parseWrapped <|> parsePrimitive
    parseWrapped  = onNextContainer (Container Context 0) parseOctetStrings
    parsePrimitive = do Other Context 0 bs <- getNext; return bs
    parseOctetString = do OctetString bs <- getNext; return bs
    parseOctetStrings = B.concat <$> getMany parseOctetString
