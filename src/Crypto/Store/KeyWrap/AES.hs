-- |
-- Module      : Crypto.Store.KeyWrap.AES
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- AES Key Wrap (<https://tools.ietf.org/html/rfc3394 RFC 3394>) and Extended
-- Key Wrap (<https://tools.ietf.org/html/rfc5649 RFC 5649>)
--
-- Should be used with a cipher from module "Crypto.Cipher.AES".
{-# LANGUAGE BangPatterns #-}
module Crypto.Store.KeyWrap.AES
    ( wrap
    , unwrap
    , wrapPad
    , unwrapPad
    ) where

import           Data.Bits
import           Data.ByteArray (ByteArray, ByteArrayAccess, Bytes)
import qualified Data.ByteArray as B
import           Data.List
import           Data.Word

import Crypto.Cipher.Types

import Foreign.Storable

import Crypto.Store.Error
import Crypto.Store.Util

type Chunked ba = [ba]
type Pair ba = (ba, ba)

-- TODO: should use a low-level AES implementation to reduce allocations

aes' :: (BlockCipher aes, ByteArray ba) => aes -> Pair ba -> ba
aes' cipher (msb, lsb) = ecbEncrypt cipher (B.append msb lsb)

aes :: (BlockCipher aes, ByteArray ba) => aes -> Pair ba -> Pair ba
aes cipher = B.splitAt 8 . aes' cipher

aesrev' :: (BlockCipher aes, ByteArray ba) => aes -> ba -> Pair ba
aesrev' cipher = B.splitAt 8 . ecbDecrypt cipher

aesrev :: (BlockCipher aes, ByteArray ba) => aes -> Pair ba -> Pair ba
aesrev cipher (msb, lsb) = aesrev' cipher (B.append msb lsb)

wrapc :: (BlockCipher aes, ByteArray ba)
      => aes -> ba -> Chunked ba -> Chunked ba
wrapc cipher iiv list = uncurry (:) $ foldl' pass (iiv, list) [0 .. 5]
  where
    !n = fromIntegral (length list)
    pass (a, l) j = go a (n * j + 1) l
    go a !_ [] = (a, [])
    go a !i (r : rs) =
        let (a', t) = aes cipher (a, r)
         in (t :) <$> go (xorWith a' i) (succ i) rs

unwrapc :: (BlockCipher aes, ByteArray ba)
        => aes -> Chunked ba -> Either StoreError (ba, Chunked ba)
unwrapc _      []         = Left (InvalidInput "KeyWrap.AES: input too short")
unwrapc cipher (iv:list)  = Right (iiv, reverse out)
  where
    (iiv, out) = foldl' pass (iv, reverse list) (reverse [0 .. 5])
    !n = fromIntegral (length list)
    pass (a, l) j = go a (n * j + n) l
    go a !_ [] = (a, [])
    go a !i (r : rs) =
        let (a', t) = aesrev cipher (xorWith a i, r)
         in (t :) <$> go a' (pred i) rs

-- | Wrap a key with the specified AES cipher.
wrap :: (BlockCipher aes, ByteArray ba) => aes -> ba -> Either StoreError ba
wrap cipher bs = unchunks . wrapc cipher iiv <$> chunks bs
  where iiv = B.replicate 8 0xA6

-- | Unwrap an encrypted key with the specified AES cipher.
unwrap :: (BlockCipher aes, ByteArray ba) => aes -> ba -> Either StoreError ba
unwrap cipher bs = unchunks <$> (check =<< unwrapc cipher =<< chunks bs)
  where
    check (iiv, out)
        | constAllEq 0xA6 iiv = Right out
        | otherwise           = Left BadChecksum

chunks :: ByteArray ba => ba -> Either StoreError (Chunked ba)
chunks bs | B.null bs       = Right []
          | B.length bs < 8 = Left (InvalidInput "KeyWrap.AES: input is not multiple of 8 bytes")
          | otherwise       = let (a, b) = B.splitAt 8 bs in (a :) <$> chunks b

unchunks :: ByteArray ba => Chunked ba -> ba
unchunks = B.concat

padMask :: Bytes
padMask = B.pack [0xA6, 0x59, 0x59, 0xA6, 0x00, 0x00, 0x00, 0x00]

pad :: ByteArray ba => Int -> ba -> Either StoreError (Pair ba)
pad inlen bs | inlen  == 0 = Left (InvalidInput "KeyWrap.AES: input is empty")
             | padlen == 8 = Right (aiv, bs)
             | otherwise   = Right (aiv, bs `B.append` B.zero padlen)
  where padlen = 8 - mod inlen 8
        aiv    = xorWith padMask (fromIntegral inlen)

unpad :: ByteArray ba => Int -> Pair ba -> Either StoreError ba
unpad inlen (aiv, b)
    | badlen         = Left BadChecksum
    | constAllEq 0 p = Right bs
    | otherwise      = Left BadChecksum
  where aivlen = fromIntegral (unxor padMask aiv)
        badlen = inlen < aivlen + 8 || inlen >= aivlen + 16
        (bs, p) = B.splitAt aivlen b

-- | Pad and wrap a key with the specified AES cipher.
wrapPad :: (BlockCipher aes, ByteArray ba) => aes -> ba -> Either StoreError ba
wrapPad cipher bs = doWrap =<< pad inlen bs
  where
    inlen = B.length bs
    doWrap (aiv, b)
        | inlen <= 8 = Right $ aes' cipher (aiv, b)
        | otherwise  = unchunks . wrapc cipher aiv <$> chunks b

-- | Unwrap and unpad an encrypted key with the specified AES cipher.
unwrapPad :: (BlockCipher aes, ByteArray ba) => aes -> ba -> Either StoreError ba
unwrapPad cipher bs = unpad inlen =<< doUnwrap
  where
    inlen = B.length bs
    doUnwrap
        | inlen == 16 = let (aiv, b) = aesrev' cipher bs in Right (aiv, b)
        | otherwise   = fmap unchunks <$> (unwrapc cipher =<< chunks bs)

xorWith :: (ByteArrayAccess bin, ByteArray bout) => bin -> Word64 -> bout
xorWith bs !i = B.copyAndFreeze bs $ \dst -> loop dst len i
  where !len = B.length bs
        loop _ 0 !_ = return ()
        loop _ _ 0  = return () -- return early (constant-time not needed)
        loop p n j  = do
            b <- peekByteOff p (n - 1)
            let mask = fromIntegral j :: Word8
            pokeByteOff p (n - 1) (xor b mask)
            loop p (n - 1) (shiftR j 8)

unxor :: (ByteArrayAccess bx, ByteArrayAccess by) => bx -> by -> Word64
unxor x y = foldl' f 0 $ zipWith xor (B.unpack x) (B.unpack y)
  where f acc z = shiftL acc 8 + fromIntegral z
