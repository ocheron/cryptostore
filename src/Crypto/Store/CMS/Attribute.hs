-- |
-- Module      : Crypto.Store.CMS.Attribute
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- CMS attributes
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Store.CMS.Attribute
    ( Attribute(..)
    , attributesASN1S
    , parseAttributes
    -- * Generic attribute
    , findAttribute
    , setAttribute
    , filterAttributes
    -- * Implementing attributes
    , setAttributeASN1S
    , runParseAttribute
    -- * Standard attributes
    , getContentTypeAttr
    , setContentTypeAttr
    , getMessageDigestAttr
    , setMessageDigestAttr
    , getSigningTimeAttr
    , setSigningTimeAttr
    , setSigningTimeAttrCurrent
    ) where

import Control.Monad.IO.Class

import Data.ASN1.Types
import Data.ByteString (ByteString)
import Data.Hourglass
import Data.Maybe (fromMaybe)

import System.Hourglass (dateCurrent)

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Type
import Crypto.Store.CMS.Util

-- | An attribute extending the parent structure with arbitrary data.
data Attribute = Attribute
    { attrType   :: OID    -- ^ Attribute type
    , attrValues :: [ASN1] -- ^ Attribute values
    }
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e Attribute where
    asn1s Attribute{..} =
        asn1Container Sequence
            (gOID attrType . asn1Container Set (gMany attrValues))

instance Monoid e => ParseASN1Object e Attribute where
    parse = onNextContainer Sequence $ do
        OID oid <- getNext
        vals <- onNextContainer Set (getMany getNext)
        return Attribute { attrType = oid, attrValues = vals }

-- | Produce the ASN.1 stream for a list of attributes.
attributesASN1S :: ASN1Elem e
                => ASN1ConstructionType -> [Attribute] -> ASN1Stream e
attributesASN1S _  []    = id
attributesASN1S ty attrs = asn1Container ty (asn1s attrs)

-- | Parse a list of attributes.
parseAttributes :: Monoid e => ASN1ConstructionType -> ParseASN1 e [Attribute]
parseAttributes ty = fromMaybe [] <$> onNextContainerMaybe ty parse

-- | Return the values for the first attribute with the specified type.
findAttribute :: OID -> [Attribute] -> Maybe [ASN1]
findAttribute oid attrs =
    case [ attrValues a | a <- attrs, attrType a == oid ] of
        []    -> Nothing
        (v:_) -> Just v

-- | Filter a list of attributes based on a predicate applied to attribute type.
filterAttributes :: (OID -> Bool) -> [Attribute] -> [Attribute]
filterAttributes p = filter (p . attrType)

-- | Add or replace an attribute in a list of attributes.
setAttribute :: OID -> [ASN1] -> [Attribute] -> [Attribute]
setAttribute oid vals = (:) attr . filterAttributes (/= oid)
  where attr = Attribute { attrType = oid, attrValues = vals }

-- | Find an attribute with the specified attribute and run a parser on the
-- attribute value when found.  'Nothing' is returned if the attribute could not
-- be found but also when the parse failed.
runParseAttribute :: OID -> [Attribute] -> ParseASN1 () a -> Maybe a
runParseAttribute oid attrs p =
    case findAttribute oid attrs of
        Nothing -> Nothing
        Just s  -> either (const Nothing) Just (runParseASN1 p s)

-- | Add or replace an attribute in a list of attributes, using 'ASN1S'.
setAttributeASN1S :: OID -> ASN1S -> [Attribute] -> [Attribute]
setAttributeASN1S oid g = setAttribute oid (g [])


-- Content type

contentType :: OID
contentType = [1,2,840,113549,1,9,3]

-- | Return the value of the @contentType@ attribute.
getContentTypeAttr :: [Attribute] -> Maybe ContentType
getContentTypeAttr attrs = runParseAttribute contentType attrs $ do
    OID oid <- getNext
    withObjectID "content type" oid return

-- | Add or replace the @contentType@ attribute in a list of attributes.
setContentTypeAttr :: ContentType -> [Attribute] -> [Attribute]
setContentTypeAttr ct = setAttributeASN1S contentType (gOID $ getObjectID ct)


-- Message digest

messageDigest :: OID
messageDigest = [1,2,840,113549,1,9,4]

-- | Return the value of the @messageDigest@ attribute.
getMessageDigestAttr :: [Attribute] -> Maybe ByteString
getMessageDigestAttr attrs = runParseAttribute messageDigest attrs $ do
    OctetString d <- getNext
    return d

-- | Add or replace the @messageDigest@ attribute in a list of attributes.
setMessageDigestAttr :: ByteString -> [Attribute] -> [Attribute]
setMessageDigestAttr d = setAttributeASN1S messageDigest (gOctetString d)


-- Signing time

signingTime :: OID
signingTime = [1,2,840,113549,1,9,5]

-- | Return the value of the @signingTime@ attribute.
getSigningTimeAttr :: [Attribute] -> Maybe DateTime
getSigningTimeAttr attrs = runParseAttribute signingTime attrs $ do
    ASN1Time _ t offset <- getNext
    let validOffset = maybe True (== TimezoneOffset 0) offset
    if validOffset
        then return t
        else fail "getSigningTimeAttr: invalid timezone"

-- | Add or replace the @signingTime@ attribute in a list of attributes.
setSigningTimeAttr :: DateTime -> [Attribute] -> [Attribute]
setSigningTimeAttr t =
    let normalize val = val { dtTime = (dtTime val) { todNSec = 0 } }
        offset = Just (TimezoneOffset 0)
        ty | t >= timeConvert (Date 2050 January 1) = TimeGeneralized
           | t <  timeConvert (Date 1950 January 1) = TimeGeneralized
           | otherwise                              = TimeUTC
     in setAttributeASN1S signingTime (gASN1Time ty (normalize t) offset)

-- | Add or replace the @signingTime@ attribute in a list of attributes with the
-- current time.  This is equivalent to calling 'setSigningTimeAttr' with the
-- result of 'dateCurrent'.
setSigningTimeAttrCurrent :: MonadIO m => [Attribute] -> m [Attribute]
setSigningTimeAttrCurrent attrs = do
    t <- liftIO dateCurrent
    return (setSigningTimeAttr t attrs)
