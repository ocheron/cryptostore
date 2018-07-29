{-# LANGUAGE ScopedTypeVariables #-}
-- | Test utilities.
module Util
    ( assertJust
    , assertRight
    , testFile
    , TestKey(..)
    , TestIV(..)
    ) where

import Data.ByteString (ByteString, pack)

import Crypto.Cipher.Types

import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

assertJust :: Maybe a -> (a -> Assertion) -> Assertion
assertJust (Just a) f = f a
assertJust Nothing  _ = assertFailure "expecting Just but got Nothing"

assertRight :: Show a => Either a b -> (b -> Assertion) -> Assertion
assertRight (Right b)  f = f b
assertRight (Left val) _ =
    assertFailure ("expecting Right but got: Left " ++ show val)

testFile :: String -> FilePath
testFile name = "tests/files/" ++ name

newtype TestKey cipher = Key ByteString deriving (Show, Eq)

instance Cipher cipher => Arbitrary (TestKey cipher) where
    arbitrary = Key . pack <$>
        case cipherKeySize cipher of
            KeySizeFixed len -> vector len
            KeySizeRange a b -> choose (a, b) >>= vector
            KeySizeEnum list -> elements list >>= vector
      where cipher = undefined :: cipher

newtype TestIV cipher = IV ByteString deriving (Show, Eq)

instance BlockCipher cipher => Arbitrary (TestIV cipher) where
    arbitrary = IV . pack <$> vector (blockSize cipher)
      where cipher = undefined :: cipher
