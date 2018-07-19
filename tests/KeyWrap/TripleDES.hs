{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | Test vectors from RFC 3217.
module KeyWrap.TripleDES (tripledeskwTests) where

import Data.ByteString (ByteString, pack)

import Crypto.Cipher.TripleDES
import Crypto.Cipher.Types
import Crypto.Error

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import Crypto.Store.KeyWrap.TripleDES

import Util

newtype Message = Message ByteString deriving (Show, Eq)

instance Arbitrary Message where
    arbitrary = Message . pack <$> vector 24

data Vector = Vector
    { vecKey        :: ByteString
    , vecIV         :: ByteString
    , vecPlaintext  :: ByteString
    , vecCiphertext :: ByteString
    }

vectorsEDE3 :: [Vector]
vectorsEDE3 =
    [ Vector
        { vecKey        = "\x25\x5e\x0d\x1c\x07\xb6\x46\xdf\xb3\x13\x4c\xc8\x43\xba\x8a\xa7\x1f\x02\x5b\x7c\x08\x38\x25\x1f"
        , vecIV         = "\x5d\xd4\xcb\xfc\x96\xf5\x45\x3b"
        , vecPlaintext  = "\x29\x23\xbf\x85\xe0\x6d\xd6\xae\x52\x91\x49\xf1\xf1\xba\xe9\xea\xb3\xa7\xda\x3d\x86\x0d\x3e\x98"
        , vecCiphertext = "\x69\x01\x07\x61\x8e\xf0\x92\xb3\xb4\x8c\xa1\x79\x6b\x23\x4a\xe9\xfa\x33\xeb\xb4\x15\x96\x04\x03\x7d\xb5\xd6\xa8\x4e\xb3\xaa\xc2\x76\x8c\x63\x27\x75\xa4\x67\xd4"
        }
    ]

vectorsEEE3 :: [Vector]
vectorsEEE3 = []

vectorsEDE2 :: [Vector]
vectorsEDE2 = []

vectorsEEE2 :: [Vector]
vectorsEEE2 = []

testCipher :: forall cipher . BlockCipher cipher => [Vector] -> cipher -> TestTree
testCipher vectors cipher =
    testGroup (cipherName cipher)
        [ localOption (QuickCheckTests 10) $ testGroup "properties"
            [ testProperty "unwrap . wrap == id" wrapUnwrapProperty
            ]
        , testGroup "vectors" (zipWith makeTest [1..] vectors)
        ]
  where
    initCipher :: BlockCipher cipher => ByteString -> cipher
    initCipher k = throwCryptoError (cipherInit k)

    wrapUnwrapProperty :: TestKey cipher -> TestIV cipher -> Message -> Property
    wrapUnwrapProperty (Key key) (IV ivBs) (Message msg) =
        (wrap ctx iv msg >>= unwrap ctx) === Right msg
      where ctx = initCipher key
            Just iv = makeIV ivBs

    makeTest :: Integer -> Vector -> TestTree
    makeTest i Vector{..} =
        testGroup (show i)
            [ testCase "Wrap"   (wrap ctx iv vecPlaintext @?= Right vecCiphertext)
            , testCase "Unwrap" (unwrap ctx vecCiphertext @?= Right vecPlaintext)
            ]
      where ctx = initCipher vecKey
            Just iv = makeIV vecIV

tripledeskwTests :: TestTree
tripledeskwTests = testGroup "KeyWrap.TripleDES"
    [ testCipher vectorsEDE3 (undefined :: DES_EDE3)
    , testCipher vectorsEEE3 (undefined :: DES_EEE3)
    , testCipher vectorsEDE2 (undefined :: DES_EDE2)
    , testCipher vectorsEEE2 (undefined :: DES_EEE2)
    ]
