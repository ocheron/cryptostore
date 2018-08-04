-- |
-- Module      : Crypto.Store.Util
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
--
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

-- | This is a strict version of &&.
(&&!) :: Bool -> Bool -> Bool
True  &&! True  = True
True  &&! False = False
False &&! True  = False
False &&! False = False
infixr 3 &&!

-- | Reverse a bytearray.
reverseBytes :: (ByteArrayAccess bin, ByteArray bout) => bin -> bout
reverseBytes = B.pack . reverse . B.unpack

-- | Test if all bytes in a bytearray are equal to the value specified.  Runs in
-- constant time.
constAllEq :: ByteArrayAccess ba => Word8 -> ba -> Bool
constAllEq b = (== 0) . foldl' fn 0 . B.unpack
  where fn acc x = acc .|. xor b x
