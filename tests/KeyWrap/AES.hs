{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | Test vectors from RFC 3394 and RFC 5649.
module KeyWrap.AES (aeskwTests) where

import Data.ByteString (ByteString, pack)

import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Error

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import Crypto.Store.KeyWrap.AES

import Util

newtype Message = Message ByteString deriving (Show, Eq)

instance Arbitrary Message where
    arbitrary = sized $ \n -> Message . pack <$> vector (8 * n)

newtype MessageP = MessageP ByteString deriving (Show, Eq)

instance Arbitrary MessageP where
    arbitrary = MessageP . pack <$> listOf1 arbitrary

data Vector = Vector
    { vecKey        :: ByteString
    , vecPlaintext  :: ByteString
    , vecCiphertext :: ByteString
    }

vectors128 :: [Vector]
vectors128 =
    [ Vector
        { vecKey        = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
        , vecPlaintext  = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
        , vecCiphertext = "\x1F\xA6\x8B\x0A\x81\x12\xB4\x47\xAE\xF3\x4B\xD8\xFB\x5A\x7B\x82\x9D\x3E\x86\x23\x71\xD2\xCF\xE5"
        }
    ]

vectors128P :: [Vector]
vectors128P = []

vectors192 :: [Vector]
vectors192 =
    [ Vector
        { vecKey        = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17"
        , vecPlaintext  = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
        , vecCiphertext = "\x96\x77\x8B\x25\xAE\x6C\xA4\x35\xF9\x2B\x5B\x97\xC0\x50\xAE\xD2\x46\x8A\xB8\xA1\x7A\xD8\x4E\x5D"
        }
    , Vector
        { vecKey        = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17"
        , vecPlaintext  = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x01\x02\x03\x04\x05\x06\x07"
        , vecCiphertext = "\x03\x1D\x33\x26\x4E\x15\xD3\x32\x68\xF2\x4E\xC2\x60\x74\x3E\xDC\xE1\xC6\xC7\xDD\xEE\x72\x5A\x93\x6B\xA8\x14\x91\x5C\x67\x62\xD2"
        }
    ]

vectors192P :: [Vector]
vectors192P =
    [ Vector
        { vecKey        = "\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8"
        , vecPlaintext  = "\xc3\x7b\x7e\x64\x92\x58\x43\x40\xbe\xd1\x22\x07\x80\x89\x41\x15\x50\x68\xf7\x38"
        , vecCiphertext = "\x13\x8b\xde\xaa\x9b\x8f\xa7\xfc\x61\xf9\x77\x42\xe7\x22\x48\xee\x5a\xe6\xae\x53\x60\xd1\xae\x6a\x5f\x54\xf3\x73\xfa\x54\x3b\x6a"
        }
    , Vector
        { vecKey        = "\x58\x40\xdf\x6e\x29\xb0\x2a\xf1\xab\x49\x3b\x70\x5b\xf1\x6e\xa1\xae\x83\x38\xf4\xdc\xc1\x76\xa8"
        , vecPlaintext  = "\x46\x6f\x72\x50\x61\x73\x69"
        , vecCiphertext = "\xaf\xbe\xb0\xf0\x7d\xfb\xf5\x41\x92\x00\xf2\xcc\xb5\x0b\xb2\x4f"
        }
    ]

vectors256 :: [Vector]
vectors256 =
    [ Vector
        { vecKey        = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
        , vecPlaintext  = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF"
        , vecCiphertext = "\x64\xE8\xC3\xF9\xCE\x0F\x5B\xA2\x63\xE9\x77\x79\x05\x81\x8A\x2A\x93\xC8\x19\x1E\x7D\x6E\x8A\xE7"
        }
    , Vector
        { vecKey        = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
        , vecPlaintext  = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x01\x02\x03\x04\x05\x06\x07"
        , vecCiphertext = "\xA8\xF9\xBC\x16\x12\xC6\x8B\x3F\xF6\xE6\xF4\xFB\xE3\x0E\x71\xE4\x76\x9C\x8B\x80\xA3\x2C\xB8\x95\x8C\xD5\xD1\x7D\x6B\x25\x4D\xA1"
        }
    , Vector
        { vecKey        = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
        , vecPlaintext  = "\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
        , vecCiphertext = "\x28\xC9\xF4\x04\xC4\xB8\x10\xF4\xCB\xCC\xB3\x5C\xFB\x87\xF8\x26\x3F\x57\x86\xE2\xD8\x0E\xD3\x26\xCB\xC7\xF0\xE7\x1A\x99\xF4\x3B\xFB\x98\x8B\x9B\x7A\x02\xDD\x21"
        }
    ]

vectors256P :: [Vector]
vectors256P = []

testCipher :: forall cipher . BlockCipher cipher
           => [Vector] -> [Vector] -> cipher -> TestTree
testCipher vec vecP cipher =
    testGroup (cipherName cipher)
        [ testGroup "properties"
            [ testProperty "unwrap . wrap == id" wrapUnwrapProperty
            , testProperty "unwrapPad . wrapPad == id" wrapUnwrapPadProperty
            ]
        , testGroup "vectors" $
            zipWith makeTest  [1..] vec ++ zipWith makeTestP [1..] vecP
        ]
  where
    initCipher :: BlockCipher cipher => ByteString -> cipher
    initCipher k = throwCryptoError (cipherInit k)

    wrapUnwrapProperty :: TestKey cipher -> Message -> Property
    wrapUnwrapProperty (Key key) (Message msg) =
        (wrap ctx msg >>= unwrap ctx) === Right msg
      where ctx = initCipher key

    makeTest :: Integer -> Vector -> TestTree
    makeTest i Vector{..} =
        testGroup (show i)
            [ testCase "Wrap"   (wrap ctx vecPlaintext @?= Right vecCiphertext)
            , testCase "Unwrap" (unwrap ctx vecCiphertext @?= Right vecPlaintext)
            ]
      where ctx = initCipher vecKey

    wrapUnwrapPadProperty :: TestKey cipher -> MessageP -> Property
    wrapUnwrapPadProperty (Key key) (MessageP msg) =
        (wrapPad ctx msg >>= unwrapPad ctx) === Right msg
      where ctx = initCipher key

    makeTestP :: Integer -> Vector -> TestTree
    makeTestP i Vector{..} =
        testGroup ("Pad" ++ show i)
            [ testCase "Wrap"   (wrapPad ctx vecPlaintext @?= Right vecCiphertext)
            , testCase "Unwrap" (unwrapPad ctx vecCiphertext @?= Right vecPlaintext)
            ]
      where ctx = initCipher vecKey

aeskwTests :: TestTree
aeskwTests = testGroup "KeyWrap.AES"
    [ testCipher vectors128 vectors128P (undefined :: AES128)
    , testCipher vectors192 vectors192P (undefined :: AES192)
    , testCipher vectors256 vectors256P (undefined :: AES256)
    ]
