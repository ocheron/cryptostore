{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
-- | Test vectors from RFC 2268.
module Cipher.RC2 (rc2Tests) where

import Data.ByteString (ByteString, pack)

import Crypto.Cipher.Types
import Crypto.Error

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import Crypto.Store.Cipher.RC2

import Util

newtype Message = Message ByteString deriving (Show, Eq)

instance Arbitrary Message where
    arbitrary = sized $ \n -> Message . pack <$> vector (8 * n)

data Vector = Vector
    { vecEffectiveKeyLength :: Int
    , vecKey                :: ByteString
    , vecPlaintext          :: ByteString
    , vecCiphertext         :: ByteString
    }

vectors :: [Vector]
vectors =
    [ Vector
        { vecEffectiveKeyLength = 63
        , vecKey                = "\x00\x00\x00\x00\x00\x00\x00\x00"
        , vecPlaintext          = "\x00\x00\x00\x00\x00\x00\x00\x00"
        , vecCiphertext         = "\xeb\xb7\x73\xf9\x93\x27\x8e\xff"
        }
    , Vector
        { vecEffectiveKeyLength = 64
        , vecKey                = "\xff\xff\xff\xff\xff\xff\xff\xff"
        , vecPlaintext          = "\xff\xff\xff\xff\xff\xff\xff\xff"
        , vecCiphertext         = "\x27\x8b\x27\xe4\x2e\x2f\x0d\x49"
        }
    , Vector
        { vecEffectiveKeyLength = 64
        , vecKey                = "\x30\x00\x00\x00\x00\x00\x00\x00"
        , vecPlaintext          = "\x10\x00\x00\x00\x00\x00\x00\x01"
        , vecCiphertext         = "\x30\x64\x9e\xdf\x9b\xe7\xd2\xc2"
        }
    , Vector
        { vecEffectiveKeyLength = 64
        , vecKey                = "\x88"
        , vecPlaintext          = "\x00\x00\x00\x00\x00\x00\x00\x00"
        , vecCiphertext         = "\x61\xa8\xa2\x44\xad\xac\xcc\xf0"
        }
    , Vector
        { vecEffectiveKeyLength = 64
        , vecKey                = "\x88\xbc\xa9\x0e\x90\x87\x5a"
        , vecPlaintext          = "\x00\x00\x00\x00\x00\x00\x00\x00"
        , vecCiphertext         = "\x6c\xcf\x43\x08\x97\x4c\x26\x7f"
        }
    , Vector
        { vecEffectiveKeyLength = 64
        , vecKey                = "\x88\xbc\xa9\x0e\x90\x87\x5a\x7f\x0f\x79\xc3\x84\x62\x7b\xaf\xb2"
        , vecPlaintext          = "\x00\x00\x00\x00\x00\x00\x00\x00"
        , vecCiphertext         = "\x1a\x80\x7d\x27\x2b\xbe\x5d\xb1"
        }
    , Vector
        { vecEffectiveKeyLength = 128
        , vecKey                = "\x88\xbc\xa9\x0e\x90\x87\x5a\x7f\x0f\x79\xc3\x84\x62\x7b\xaf\xb2"
        , vecPlaintext          = "\x00\x00\x00\x00\x00\x00\x00\x00"
        , vecCiphertext         = "\x22\x69\x55\x2a\xb0\xf8\x5c\xa6"
        }
    , Vector
        { vecEffectiveKeyLength = 129
        , vecKey                = "\x88\xbc\xa9\x0e\x90\x87\x5a\x7f\x0f\x79\xc3\x84\x62\x7b\xaf\xb2\x16\xf8\x0a\x6f\x85\x92\x05\x84\xc4\x2f\xce\xb0\xbe\x25\x5d\xaf\x1e"
        , vecPlaintext          = "\x00\x00\x00\x00\x00\x00\x00\x00"
        , vecCiphertext         = "\x5b\x78\xd3\xa4\x3d\xff\xf1\xf1"
        }
    ]

testCipher :: forall cipher . BlockCipher cipher
           => String -> [Vector] -> cipher -> TestTree
testCipher name vec _cipher =
    testGroup name
        [ testGroup "properties"
            [ testProperty "decrypt . encrypt == id" encryptDecryptProperty
            ]
        , testGroup "vectors" $ zipWith makeTest [1..] vec
        ]
  where
    initCipher :: BlockCipher cipher => ByteString -> cipher
    initCipher k = throwCryptoError (cipherInit k)

    encryptDecryptProperty :: TestKey cipher -> Message -> Property
    encryptDecryptProperty (Key key) (Message msg) =
        ecbDecrypt ctx (ecbEncrypt ctx msg) === msg
      where ctx = initCipher key

    makeTest :: Integer -> Vector -> TestTree
    makeTest i Vector{..} =
        testGroup (show i)
            [ testCase "Encrypt" (ecbEncrypt ctx vecPlaintext @?= vecCiphertext)
            , testCase "Decrypt" (ecbDecrypt ctx vecCiphertext @?= vecPlaintext)
            ]
      where
        ctx = throwCryptoError $
            rc2WithEffectiveKeyLength vecEffectiveKeyLength vecKey

rc2Tests :: TestTree
rc2Tests = testCipher "Cipher.RC2" vectors (undefined :: RC2)
