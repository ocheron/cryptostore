-- |
-- Module      : Crypto.Store.CMS.Attribute
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- CMS attributes
{-# LANGUAGE RecordWildCards #-}
module Crypto.Store.CMS.Attribute
    ( Attribute(..)
    , attributesASN1S
    , parseAttributes
    , findAttribute
    , setAttribute
    , filterAttributes
    ) where

import Data.ASN1.Parse
import Data.ASN1.Types
import Data.Maybe (fromMaybe)

import Crypto.Store.ASN1.Generate
import Crypto.Store.CMS.Util

-- | An attribute extending the CMS structure with arbitrary data.
data Attribute = Attribute
    { attrType   :: OID    -- ^ Attribute type
    , attrValues :: [ASN1] -- ^ Attribute values
    }
    deriving (Show,Eq)

instance ParseASN1Object Attribute where
    asn1s Attribute{..} =
        asn1Container Sequence
            (gOID attrType . asn1Container Set (gMany attrValues))

    parse = onNextContainer Sequence $ do
        OID oid <- getNext
        vals <- onNextContainer Set (getMany getNext)
        return Attribute { attrType = oid, attrValues = vals }

-- | Produce the ASN.1 stream for a list of attributes.
attributesASN1S :: ASN1ConstructionType -> [Attribute] -> ASN1S
attributesASN1S _  []    = id
attributesASN1S ty attrs = asn1Container ty (asn1s attrs)

-- | Parse a list of attributes.
parseAttributes :: ASN1ConstructionType -> ParseASN1 [Attribute]
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
