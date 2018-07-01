-- |
-- Module      : Crypto.Store.PKCS8.EC
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Additional EC utilities.
module Crypto.Store.PKCS8.EC
    ( numBytes
    , curveSizeBytes
    , curveOrderBytes
    , curveNameOID
    , getSerializedPoint
    , module Data.X509.EC
    ) where

import           Data.ASN1.OID
import qualified Data.ByteString as B
import           Data.Maybe (fromMaybe)

import Data.X509
import Data.X509.EC

import Crypto.Number.Basic (numBits)
import Crypto.Number.Serialize (i2ospOf_)
import Crypto.PubKey.ECC.Prim
import Crypto.PubKey.ECC.Types

import Crypto.Store.CMS.Util

-- | Number of bytes necessary to serialize n bits.
bitsToBytes :: Int -> Int
bitsToBytes n = (n + 7) `div` 8

-- | Number of bytes necessary to serialize an integer.
numBytes :: Integer -> Int
numBytes = bitsToBytes . numBits

-- | Number of bytes to serialize a field element.
curveSizeBytes :: Curve -> Int
curveSizeBytes = bitsToBytes . curveSizeBits

-- | Number of bytes to serialize a scalar.
curveOrderBytes :: Curve -> Int
curveOrderBytes = bitsToBytes . numBits . ecc_n . common_curve

-- | Transform a private scalar to a point in uncompressed format.
getSerializedPoint :: Curve -> PrivateNumber -> SerializedPoint
getSerializedPoint curve d = SerializedPoint (serializePoint pt)
  where
    pt = pointBaseMul curve d
    bs = i2ospOf_ (curveSizeBytes curve)

    serializePoint PointO      = B.singleton 0
    serializePoint (Point x y) = B.cons 4 (B.append (bs x) (bs y))

-- | Return the OID associated to a curve name.
curveNameOID :: CurveName -> OID
curveNameOID name =
    fromMaybe (error $ "PKCS8: OID unknown for EC curve " ++ show name)
        (lookupOID curvesOIDTable name)

curvesOIDTable :: OIDTable CurveName
curvesOIDTable =
    [ (SEC_p112r1, [1,3,132,0,6])
    , (SEC_p112r2, [1,3,132,0,7])
    , (SEC_p128r1, [1,3,132,0,28])
    , (SEC_p128r2, [1,3,132,0,29])
    , (SEC_p160k1, [1,3,132,0,9])
    , (SEC_p160r1, [1,3,132,0,8])
    , (SEC_p160r2, [1,3,132,0,30])
    , (SEC_p192k1, [1,3,132,0,31])
    , (SEC_p192r1, [1,2,840,10045,3,1,1])
    , (SEC_p224k1, [1,3,132,0,32])
    , (SEC_p224r1, [1,3,132,0,33])
    , (SEC_p256k1, [1,3,132,0,10])
    , (SEC_p256r1, [1,2,840,10045,3,1,7])
    , (SEC_p384r1, [1,3,132,0,34])
    , (SEC_p521r1, [1,3,132,0,35])
    , (SEC_t113r1, [1,3,132,0,4])
    , (SEC_t113r2, [1,3,132,0,5])
    , (SEC_t131r1, [1,3,132,0,22])
    , (SEC_t131r2, [1,3,132,0,23])
    , (SEC_t163k1, [1,3,132,0,1])
    , (SEC_t163r1, [1,3,132,0,2])
    , (SEC_t163r2, [1,3,132,0,15])
    , (SEC_t193r1, [1,3,132,0,24])
    , (SEC_t193r2, [1,3,132,0,25])
    , (SEC_t233k1, [1,3,132,0,26])
    , (SEC_t233r1, [1,3,132,0,27])
    , (SEC_t239k1, [1,3,132,0,3])
    , (SEC_t283k1, [1,3,132,0,16])
    , (SEC_t283r1, [1,3,132,0,17])
    , (SEC_t409k1, [1,3,132,0,36])
    , (SEC_t409r1, [1,3,132,0,37])
    , (SEC_t571k1, [1,3,132,0,38])
    , (SEC_t571r1, [1,3,132,0,39])
    ]
