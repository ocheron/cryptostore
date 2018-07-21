-- |
-- Module      : Crypto.Store.ASN1.Generate
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Generating ASN.1
module Crypto.Store.ASN1.Generate
    ( ASN1Stream
    , ASN1Elem()
    , ASN1P()
    , ASN1PS
    , asn1Container
    , gNull
    , gIntVal
    , gOID
    , gASN1String
    , gOctetString
    , gBitString
    , gASN1Time
    , gMany
    , gEncoded
    , optASN1S
    , encodeASN1S
    ) where

import           Data.ASN1.BinaryEncoding
import           Data.ASN1.BinaryEncoding.Raw
import           Data.ASN1.BitArray
import           Data.ASN1.Encoding
import           Data.ASN1.OID
import           Data.ASN1.Types
import qualified Data.ByteArray as B
import           Data.ByteString (ByteString)

import Time.Types (DateTime, TimezoneOffset)

-- | A stream of ASN.1 elements.
type ASN1Stream e = [e] -> [e]

-- | Elements in an ASN.1 stream.
class ASN1Elem e where
    -- | Create a container from an inner ASN.1 stream.
    asn1Container :: ASN1ConstructionType -> ASN1Stream e -> ASN1Stream e
    -- | Generate a list of ASN.1 elements.
    gMany :: [ASN1] -> ASN1Stream e
    -- | Generate one ASN.1 element.
    gOne :: ASN1 -> ASN1Stream e

instance ASN1Elem ASN1 where
    asn1Container ty f = (Start ty :) . f . (End ty :)
    gMany = (++)
    gOne = (:)

-- | Extend the 'ASN1' type to be able to encode to ASN.1 even when some parts
-- of the stream have already been encoded.
data ASN1P
    = ASN1Prim [ASN1]
      -- ^ Primitive elements (or constructed types that are fully terminated)
    | ASN1Container !ASN1ConstructionType [ASN1P]
      -- ^ Constructed type with inner structure kept
    | ASN1Encoded !ByteString
      -- ^ A part which has already been encoded

instance ASN1Elem ASN1P where
    asn1Container ty f = (ASN1Container ty (f []) :)
    gMany asn1 = (ASN1Prim asn1 :)
    gOne = gMany . (:[])

-- | Prepend a list of 'ASN1P'.
type ASN1PS = ASN1Stream ASN1P

-- | Encode to ASN.1 a list of 'ASN1P' elements.  Outer encoding will be DER,
-- but partially encoded inner 'ASN1Encoded' elements many have any encoding.
pEncode :: [ASN1P] -> ByteString
pEncode x = let (_, f) = run x in f B.empty
  where
    run []                   = (0, id)
    run (ASN1Prim asn1 : as) = (B.length p + r, B.append p . ps)
      where p       = encodeASN1' DER asn1
            (r, ps) = run as
    run (ASN1Encoded p : as) = (B.length p + r, B.append p . ps)
      where (r, ps) = run as
    run (ASN1Container ty children : as) =
        (B.length header + l + r, B.append header . p . ps)
      where (l, p)  = run children
            (r, ps) = run as
            header  = toByteString [Header $ ASN1Header cl tg True $ makeLen l]
            (cl, tg) =
                case ty of
                    Container tyClass tyTag -> (tyClass, tyTag)
                    Sequence -> (Universal, 0x10)
                    Set -> (Universal, 0x11)

    makeLen len
        | len < 0x80 = LenShort len
        | otherwise  = LenLong (nbBytes len) len
    nbBytes nb = if nb > 255 then 1 + nbBytes (nb `div` 256) else 1

-- | Generate a 'Null' ASN.1 element.
gNull :: ASN1Elem e => ASN1Stream e
gNull = gOne Null

-- | Generate an 'IntVal' ASN.1 element.
gIntVal :: ASN1Elem e => Integer -> ASN1Stream e
gIntVal = gOne . IntVal

-- | Generate an 'OID' ASN.1 element.
gOID :: ASN1Elem e => OID -> ASN1Stream e
gOID = gOne . OID

-- | Generate an 'ASN1String' ASN.1 element.
gASN1String :: ASN1Elem e => ASN1CharacterString -> ASN1Stream e
gASN1String = gOne . ASN1String

-- | Generate an 'OctetString' ASN.1 element.
gOctetString :: ASN1Elem e => ByteString -> ASN1Stream e
gOctetString = gOne . OctetString

-- | Generate a 'BitString' ASN.1 element.
gBitString :: ASN1Elem e => BitArray -> ASN1Stream e
gBitString = gOne . BitString

-- | Generate an 'ASN1Time' ASN.1 element.
gASN1Time :: ASN1Elem e
          => ASN1TimeType -> DateTime -> Maybe TimezoneOffset -> ASN1Stream e
gASN1Time a b c = gOne (ASN1Time a b c)

-- | Generate ASN.1 for an optional value.
optASN1S :: Maybe a -> (a -> ASN1Stream e) -> ASN1Stream e
optASN1S Nothing    _  = id
optASN1S (Just val) fn = fn val

-- | Generate ASN.1 for a part of the stream which is already encoded.
gEncoded :: ByteString -> ASN1PS
gEncoded = (:) . ASN1Encoded

-- | Encode the ASN.1 stream to DER format (except for inner parts that are
-- already encoded and may use another format).
encodeASN1S :: ASN1PS -> ByteString
encodeASN1S asn1 = pEncode (asn1 [])
