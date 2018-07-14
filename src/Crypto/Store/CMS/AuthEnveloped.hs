-- |
-- Module      : Crypto.Store.CMS.AuthEnveloped
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
--
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Store.CMS.AuthEnveloped
    ( AuthEnvelopedData(..)
    , encodeAuthAttrs
    ) where

import Control.Monad

import Data.ASN1.Types
import Data.ByteArray (convert)
import Data.ByteString (ByteString)

import Crypto.Cipher.Types

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Attribute
import Crypto.Store.CMS.Encrypted
import Crypto.Store.CMS.Enveloped
import Crypto.Store.CMS.Type
import Crypto.Store.CMS.Util

-- | Authenticated-enveloped content information.
--
-- TODO: originator info is missing
data AuthEnvelopedData = AuthEnvelopedData
    { aeRecipientInfos :: [RecipientInfo]
      -- ^ Information for recipients, allowing to decrypt the content
    , aeContentType :: ContentType
      -- ^ Inner content type
    , aeContentEncryptionParams :: ASN1ObjectExact AuthContentEncryptionParams
      -- ^ Encryption algorithm
    , aeEncryptedContent :: EncryptedContent
      -- ^ Encrypted content info
    , aeAuthAttrs :: [Attribute]
      -- ^ Optional authenticated attributes
    , aeMAC :: MessageAuthenticationCode
      -- ^ Message authentication code
    , aeUnauthAttrs :: [Attribute]
      -- ^ Optional unauthenticated attributes
    }
    deriving (Show,Eq)

instance ProduceASN1Object ASN1P AuthEnvelopedData where
    asn1s AuthEnvelopedData{..} =
        asn1Container Sequence (ver . ris . eci . aa . tag . ua)
      where
        ver = gIntVal 0
        ris = asn1Container Set (asn1s aeRecipientInfos)
        eci = encryptedContentInfoASN1S
                  (aeContentType, aeContentEncryptionParams, aeEncryptedContent)
        aa  = attributesASN1S (Container Context 1) aeAuthAttrs
        tag = gOctetString (convert aeMAC)
        ua  = attributesASN1S (Container Context 2) aeUnauthAttrs

instance ParseASN1Object [ASN1Event] AuthEnvelopedData where
    parse =
        onNextContainer Sequence $ do
            IntVal v <- getNext
            when (v /= 0) $
                throwParseError ("AuthEnvelopedData: parsed invalid version: " ++ show v)
            ris <- onNextContainer Set parse
            (ct, params, ec) <- parseEncryptedContentInfo
            aAttrs <- parseAttributes (Container Context 1)
            OctetString tag <- getNext
            uAttrs <- parseAttributes (Container Context 2)
            return AuthEnvelopedData { aeContentType = ct
                                     , aeRecipientInfos = ris
                                     , aeContentEncryptionParams = params
                                     , aeEncryptedContent = ec
                                     , aeAuthAttrs = aAttrs
                                     , aeMAC = AuthTag $ convert tag
                                     , aeUnauthAttrs = uAttrs
                                     }

-- | Return the DER encoding of the attributes as required for AAD.
encodeAuthAttrs :: [Attribute] -> ByteString
encodeAuthAttrs [] = mempty
encodeAuthAttrs l  = encodeASN1S $ asn1Container Set (asn1s l)
