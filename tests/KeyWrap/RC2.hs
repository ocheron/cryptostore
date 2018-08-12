{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | Test vectors from RFC 3217.
module KeyWrap.RC2 (rc2kwTests) where

import           Data.ByteString (ByteString)
import qualified Data.ByteString as B

import Crypto.Cipher.Types
import Crypto.Error

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import Crypto.Store.Cipher.RC2
import Crypto.Store.Error
import Crypto.Store.KeyWrap.RC2

import X509.Instances () -- for instance MonadRandom Gen
import Util

newtype Message = Message ByteString deriving (Show, Eq)

instance Arbitrary Message where
    arbitrary = Message . B.pack <$> (choose (0, 255) >>= vector)

data Vector = Vector
    { vecEKL        :: Int
    , vecKey        :: ByteString
    , vecPad        :: ByteString
    , vecIV         :: ByteString
    , vecPlaintext  :: ByteString
    , vecCiphertext :: ByteString
    }

vectors :: [Vector]
vectors =
    [ Vector
        { vecEKL        = 40
        , vecKey        = "\xfd\x04\xfd\x08\x06\x07\x07\xfb\x00\x03\xfe\xff\xfd\x02\xfe\x05"
        , vecPad        = "\x48\x45\xcc\xe7\xfd\x12\x50"
        , vecIV         = "\xc7\xd9\x00\x59\xb2\x9e\x97\xf7"
        , vecPlaintext  = "\xb7\x0a\x25\xfb\xc9\xd8\x6a\x86\x05\x0c\xe0\xd7\x11\xea\xd4\xd9"
        , vecCiphertext = "\x70\xe6\x99\xfb\x57\x01\xf7\x83\x33\x30\xfb\x71\xe8\x7c\x85\xa4\x20\xbd\xc9\x9a\xf0\x5d\x22\xaf\x5a\x0e\x48\xd3\x5f\x31\x38\x98\x6c\xba\xaf\xb4\xb2\x8d\x4f\x35"
        }
    , Vector
        { vecEKL        = 128 -- from RFC Errata
        , vecKey        = "\xfd\x04\xfd\x08\x06\x07\x07\xfb\x00\x03\xfe\xff\xfd\x02\xfe\x05"
        , vecPad        = "\x48\x45\xcc\xe7\xfd\x12\x50"
        , vecIV         = "\xc7\xd9\x00\x59\xb2\x9e\x97\xf7"
        , vecPlaintext  = "\xb7\x0a\x25\xfb\xc9\xd8\x6a\x86\x05\x0c\xe0\xd7\x11\xea\xd4\xd9"
        , vecCiphertext = "\xf4\xd8\x02\x1c\x1e\xa4\x63\xd2\x17\xa9\xeb\x69\x29\xff\xa5\x77\x36\xd3\xe2\x03\x86\xc9\x09\x93\x83\x5b\x4b\xe4\xad\x8d\x8a\x1b\xc6\x3b\x25\xde\x2b\xf7\x79\x93"
        }
    ]

rc2kwTests :: TestTree
rc2kwTests =
    testGroup "KeyWrap.RC2"
        [ testGroup "properties"
            [ testProperty "unwrap . wrap == id" wrapUnwrapProperty
            ]
        , testGroup "vectors" (zipWith makeTest [1..] vectors)
        ]
  where
    initCipher :: Int -> ByteString -> RC2
    initCipher ekl k = throwCryptoError (rc2WithEffectiveKeyLength ekl k)

    wrapUnwrapProperty :: TestKey RC2 -> TestIV RC2 -> Message -> Gen Property
    wrapUnwrapProperty (Key key) (IV ivBs) (Message msg) = do
        ekl <- choose (1, 1024)
        let ctx = initCipher ekl key
        wrapped <- wrap ctx iv msg
        return $ (wrapped >>= unwrap ctx) === Right msg
      where Just iv = makeIV ivBs

    makeTest :: Integer -> Vector -> TestTree
    makeTest i Vector{..} =
        testGroup (show i)
            [ testCase "Wrap" (doWrap ctx iv vecPlaintext @?= Right vecCiphertext)
            , testCase "Unwrap" (unwrap ctx vecCiphertext @?= Right vecPlaintext)
            ]
      where ctx = initCipher vecEKL vecKey
            Just iv = makeIV vecIV
            doWrap = wrap' Left withRandomPad
            withRandomPad f len
                | B.length vecPad /= len = Left (InvalidInput "unexpected length")
                | otherwise              = Right (f vecPad)
