-- |
-- Module      : Crypto.Store.Util
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
--
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE MagicHash #-}
module Crypto.Store.Util
    ( (&&!)
    , reverseBytes
    , constAllEq
    , mapLeft
    , mapAsWord64LE
    ) where

import           Data.Bits
import           Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteArray as B
import           Data.List
import           Data.Memory.Endian
import           Data.Word

import           Foreign.Ptr (plusPtr)
import           Foreign.Storable

import GHC.Exts

-- | This is a strict version of &&.
(&&!) :: Bool -> Bool -> Bool
(&&!) x y = isTrue# (andI# (getTag# x) (getTag# y))
  where getTag# !z = dataToTag# z
infixr 3 &&!

-- | Reverse a bytearray.
reverseBytes :: ByteArray ba => ba -> ba
#if MIN_VERSION_memory(0,14,18)
reverseBytes = B.reverse
#else
reverseBytes = B.pack . reverse . B.unpack
#endif

-- | Test if all bytes in a bytearray are equal to the value specified.  Runs in
-- constant time.
constAllEq :: ByteArrayAccess ba => Word8 -> ba -> Bool
constAllEq b = (== 0) . foldl' fn 0 . B.unpack
  where fn acc x = acc .|. xor b x

-- | Map over the left value.
mapLeft :: (a -> b) -> Either a c -> Either b c
mapLeft f (Left a)  = Left (f a)
mapLeft _ (Right c) = Right c

-- | Same as 'Data.ByteArray.Mapping.mapAsWord64' but with little-endian words.
mapAsWord64LE :: ByteArray bs => (Word64 -> Word64) -> bs -> bs
mapAsWord64LE f bs =
    B.allocAndFreeze len $ \dst ->
        B.withByteArray bs $ \src ->
            loop (len `div` 8) dst src
  where
        len = B.length bs

        loop :: Int -> Ptr (LE Word64) -> Ptr (LE Word64) -> IO ()
        loop 0 _ _ = return ()
        loop i d s = do
            w <- peek s
            let r = f (fromLE w)
            poke d (toLE r)
            loop (i - 1) (d `plusPtr` 8) (s `plusPtr` 8)
