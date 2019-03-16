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
{-# LANGUAGE MultiParamTypeClasses #-}
module Crypto.Store.CMS.Info
    ( ContentInfo(..)
    , getContentType
    , Encapsulates
    , isAttached
    , fromAttached
    , toAttachedCI
    , isDetached
    , fromDetached
    , toDetachedCI
    ) where

import Control.Monad.Fail (MonadFail)

import Data.ASN1.Types
import Data.ByteString (ByteString)
import Data.Maybe (isJust, isNothing)

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
                 | SignedDataCI (SignedData (Encap EncapsulatedContent))
                   -- ^ Signed content info
                 | EnvelopedDataCI (EnvelopedData (Encap EncryptedContent))
                   -- ^ Enveloped content info
                 | DigestedDataCI (DigestedData (Encap EncapsulatedContent))
                   -- ^ Content info with associated digest
                 | EncryptedDataCI (EncryptedData (Encap EncryptedContent))
                   -- ^ Encrypted content info
                 | AuthenticatedDataCI (AuthenticatedData (Encap EncapsulatedContent))
                   -- ^ Authenticatedcontent info
                 | AuthEnvelopedDataCI (AuthEnvelopedData (Encap EncryptedContent))
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


-- Encapsulation

-- | Class of data structures with inner content that may be stored externally.
-- This class has instances for each CMS content type containing other
-- encapsulated or encrypted content info.
--
-- Functions 'fromAttached' and 'fromDetached' are used to introspect
-- encapsulation state (attached or detached), and recover a data structure with
-- actionable content.
--
-- Functions 'toAttachedCI' and 'toDetachedCI' are needed to decide about the
-- outer encapsulation state and build a 'ContentInfo'.
class Encapsulates struct where
    getInner :: struct a -> a
    setInner :: struct a -> b -> struct b
    toCI :: struct (Encap ByteString) -> ContentInfo

instance Encapsulates SignedData where
    getInner = sdEncapsulatedContent
    setInner s c = s { sdEncapsulatedContent = c }
    toCI = SignedDataCI

instance Encapsulates EnvelopedData where
    getInner = evEncryptedContent
    setInner s c = s { evEncryptedContent = c }
    toCI = EnvelopedDataCI

instance Encapsulates DigestedData where
    getInner = ddEncapsulatedContent
    setInner s c = s { ddEncapsulatedContent = c }
    toCI = DigestedDataCI

instance Encapsulates EncryptedData where
    getInner = edEncryptedContent
    setInner s c = s { edEncryptedContent = c }
    toCI = EncryptedDataCI

instance Encapsulates AuthenticatedData where
    getInner = adEncapsulatedContent
    setInner s c = s { adEncapsulatedContent = c }
    toCI = AuthenticatedDataCI

instance Encapsulates AuthEnvelopedData where
    getInner = aeEncryptedContent
    setInner s c = s { aeEncryptedContent = c }
    toCI = AuthEnvelopedDataCI

-- | Return 'True' when the encapsulated content is attached.
isAttached :: Encapsulates struct => struct (Encap a) -> Bool
isAttached = isJust . fromAttached

-- | Unwrap the encapsulation, assuming the inner content is inside the data
-- structure.  The monadic computation fails if the content was detached.
fromAttached :: (MonadFail m, Encapsulates struct) => struct (Encap a) -> m (struct a)
fromAttached s = fromEncap err (return . setInner s) (getInner s)
  where err = fail "fromAttached: detached"

-- | Keep the content inside the data structure.
toAttached :: Encapsulates struct => struct a -> struct (Encap a)
toAttached s = setInner s (Attached $ getInner s)

-- | Transform the data structure into a content info, keeping the encapsulated
-- content attached.  May be applied to structures with 'EncapsulatedContent' or
-- 'EncryptedContent'.
toAttachedCI :: Encapsulates struct => struct ByteString -> ContentInfo
toAttachedCI = toCI . toAttached

-- | Return 'True' when the encapsulated content is detached.
isDetached :: Encapsulates struct => struct (Encap a) -> Bool
isDetached = isNothing . fromAttached

-- | Recover the original data structure from a detached encapsulation and the
-- external content.  The monadic computation fails if the content was attached.
fromDetached :: (MonadFail m, Encapsulates struct) => b -> struct (Encap a) -> m (struct b)
fromDetached c s = fromEncap (return $ setInner s c) err (getInner s)
  where err _ = fail "fromDetached: attached"

-- | Remove the content from the data structure to store it externally.
toDetached :: Encapsulates struct => struct a -> (a, struct (Encap a))
toDetached s = (getInner s, setInner s Detached)

-- | Transform the data structure into a content info, detaching the
-- encapsulated content.  May be applied to structures with
-- 'EncapsulatedContent' or 'EncryptedContent'.
toDetachedCI :: Encapsulates struct => struct ByteString -> (ByteString, ContentInfo)
toDetachedCI = fmap toCI . toDetached
