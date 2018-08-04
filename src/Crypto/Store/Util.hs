-- |
-- Module      : Crypto.Store.Util
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
--
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE MagicHash #-}
module Crypto.Store.Util
    ( (&&!)
    , reverseBytes
    , constAllEq
    ) where

import           Data.Bits
import           Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteArray as B
import           Data.List
import           Data.Word

import GHC.Exts

-- | This is a strict version of &&.
(&&!) :: Bool -> Bool -> Bool
(&&!) x y = isTrue# (andI# (getTag# x) (getTag# y))
  where getTag# !z = dataToTag# z
infixr 3 &&!

-- | Reverse a bytearray.
reverseBytes :: (ByteArrayAccess bin, ByteArray bout) => bin -> bout
reverseBytes = B.pack . reverse . B.unpack

-- | Test if all bytes in a bytearray are equal to the value specified.  Runs in
-- constant time.
constAllEq :: ByteArrayAccess ba => Word8 -> ba -> Bool
constAllEq b = (== 0) . foldl' fn 0 . B.unpack
  where fn acc x = acc .|. xor b x
