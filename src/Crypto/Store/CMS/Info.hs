-- |
-- Module      : Crypto.Store.CMS.Info
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- CMS content information.
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.Store.CMS.Info
    ( ContentInfo(..)
    , getContentType
    ) where

import Data.ASN1.Types
import Data.ByteString (ByteString)

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Authenticated
import Crypto.Store.CMS.AuthEnveloped
import Crypto.Store.CMS.Digested
import Crypto.Store.CMS.Encrypted
import Crypto.Store.CMS.Enveloped
import Crypto.Store.CMS.Signed
import Crypto.Store.CMS.Type
import Crypto.Store.CMS.Util

-- | Get the type of a content info.
getContentType :: ContentInfo -> ContentType
getContentType (DataCI _)              = DataType
getContentType (SignedDataCI _)        = SignedDataType
getContentType (EnvelopedDataCI _)     = EnvelopedDataType
getContentType (DigestedDataCI _)      = DigestedDataType
getContentType (EncryptedDataCI _)     = EncryptedDataType
getContentType (AuthenticatedDataCI _) = AuthenticatedDataType
getContentType (AuthEnvelopedDataCI _) = AuthEnvelopedDataType


-- ContentInfo

-- | CMS content information.
data ContentInfo = DataCI ByteString
                   -- ^ Arbitrary octet string
                 | SignedDataCI (SignedData EncapsulatedContent)
                   -- ^ Signed content info
                 | EnvelopedDataCI (EnvelopedData EncryptedContent)
                   -- ^ Enveloped content info
                 | DigestedDataCI (DigestedData EncapsulatedContent)
                   -- ^ Content info with associated digest
                 | EncryptedDataCI (EncryptedData EncryptedContent)
                   -- ^ Encrypted content info
                 | AuthenticatedDataCI (AuthenticatedData EncapsulatedContent)
                   -- ^ Authenticatedcontent info
                 | AuthEnvelopedDataCI (AuthEnvelopedData EncryptedContent)
                   -- ^ Authenticated-enveloped content info
                 deriving (Show,Eq)

instance ProduceASN1Object ASN1P ContentInfo where
    asn1s ci = asn1Container Sequence (oid . cont)
      where oid = gOID $ getObjectID $ getContentType ci
            cont = asn1Container (Container Context 0) inner
            inner =
                case ci of
                    DataCI bs              -> dataASN1S bs
                    SignedDataCI ed        -> asn1s ed
                    EnvelopedDataCI ed     -> asn1s ed
                    DigestedDataCI dd      -> asn1s dd
                    EncryptedDataCI ed     -> asn1s ed
                    AuthenticatedDataCI ad -> asn1s ad
                    AuthEnvelopedDataCI ae -> asn1s ae

instance ParseASN1Object [ASN1Event] ContentInfo where
    parse =
        onNextContainer Sequence $ do
            OID oid <- getNext
            withObjectID "content type" oid $ \ct ->
                onNextContainer (Container Context 0) (parseInner ct)
      where
        parseInner DataType              = DataCI <$> parseData
        parseInner SignedDataType        = SignedDataCI <$> parse
        parseInner EnvelopedDataType     = EnvelopedDataCI <$> parse
        parseInner DigestedDataType      = DigestedDataCI <$> parse
        parseInner EncryptedDataType     = EncryptedDataCI <$> parse
        parseInner AuthenticatedDataType = AuthenticatedDataCI <$> parse
        parseInner AuthEnvelopedDataType = AuthEnvelopedDataCI <$> parse


-- Data

dataASN1S :: ASN1Elem e => ByteString -> ASN1Stream e
dataASN1S = gOctetString

parseData :: Monoid e => ParseASN1 e ByteString
parseData = do
    next <- getNext
    case next of
        OctetString bs -> return bs
        _              -> throwParseError "Data: parsed unexpected content"
