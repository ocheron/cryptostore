-- |
-- Module      : Crypto.Store.ASN1.Generate
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Generating ASN.1
module Crypto.Store.ASN1.Generate
    ( asn1Container
    , gNull
    , gIntVal
    , gOID
    , gOctetString
    , gBitString
    , gASN1Time
    , gMany
    , optASN1S
    ) where

import           Data.ASN1.BitArray
import           Data.ASN1.OID
import           Data.ASN1.Types
import           Data.ByteString (ByteString)

import Time.Types (DateTime, TimezoneOffset)

-- | Create a container from an inner stream of 'ASN1'.
asn1Container :: ASN1ConstructionType -> ASN1S -> ASN1S
asn1Container ty f = (Start ty :) . f . (End ty :)

-- | Generate a 'Null' ASN.1 element.
gNull :: ASN1S
gNull = gOne Null

-- | Generate an 'IntVal' ASN.1 element.
gIntVal :: Integer -> ASN1S
gIntVal = gOne . IntVal

-- | Generate an 'OID' ASN.1 element.
gOID :: OID -> ASN1S
gOID = gOne . OID

-- | Generate an 'OctetString' ASN.1 element.
gOctetString :: ByteString -> ASN1S
gOctetString = gOne . OctetString

-- | Generate a 'BitString' ASN.1 element.
gBitString :: BitArray -> ASN1S
gBitString = gOne . BitString

-- | Generate an 'ASN1Time' ASN.1 element.
gASN1Time :: ASN1TimeType -> DateTime -> Maybe TimezoneOffset -> ASN1S
gASN1Time a b c = gOne (ASN1Time a b c)

-- | Generate a list of ASN.1 elements.
gMany :: [ASN1] -> ASN1S
gMany asn1 = (asn1 ++)

-- | Generate an ASN.1 element.
gOne :: ASN1 -> ASN1S
gOne = gMany . (:[])

-- | Generate ASN.1 for an optional value.
optASN1S :: Maybe a -> (a -> ASN1S) -> ASN1S
optASN1S Nothing    _  = id
optASN1S (Just val) fn = fn val
