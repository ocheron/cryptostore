-- |
-- Module      : Crypto.Store.Cipher.RC2.Primitive
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : stable
-- Portability : good
--
{-# LANGUAGE Rank2Types #-}
module Crypto.Store.Cipher.RC2.Primitive
    ( Key
    , buildKey
    , encrypt
    , decrypt
    ) where

import Basement.Block
import Basement.Compat.IsList
import Basement.Endianness
import Basement.Types.OffsetSize

import Control.Monad (forM_)

import           Data.Bits
import           Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteArray as B
import           Data.Word

import Foreign.Storable


-- | Expanded RC2 key
newtype Key = Key (Block Word16) -- [ K[0], K[1], ..., K[63] ]

data Q = Q {-# UNPACK #-} !Word16 {-# UNPACK #-} !Word16
           {-# UNPACK #-} !Word16 {-# UNPACK #-} !Word16


-- Utilities

decomp64 :: Word64 -> Q
decomp64 x =
    let d = fromIntegral (x `shiftR` 48)
        c = fromIntegral (x `shiftR` 32)
        b = fromIntegral (x `shiftR` 16)
        a = fromIntegral  x
    in Q a b c d

comp64 :: Q -> Word64
comp64 (Q a b c d) =
    (fromIntegral d `shiftL` 48) .|.
    (fromIntegral c `shiftL` 32) .|.
    (fromIntegral b `shiftL` 16) .|.
     fromIntegral a

getR :: Q -> Word8 -> Word16
getR (Q a b c d) i =
    case i .&. 3 of
        0 -> a
        1 -> b
        2 -> c
        _ -> d
{-# INLINE getR #-}

setR :: Q -> Word8 -> Word16 -> Q
setR (Q a b c d) i x =
    case i .&. 3 of
        0 -> Q x b c d
        1 -> Q a x c d
        2 -> Q a b x d
        _ -> Q a b c x
{-# INLINE setR #-}

rol :: Word8 -> Word16 -> Word16
rol i =
    case i .&. 3 of
        0 -> flip rotateL 1
        1 -> flip rotateL 2
        2 -> flip rotateL 3
        _ -> flip rotateL 5
{-# INLINE rol #-}

ror :: Word8 -> Word16 -> Word16
ror i =
    case i .&. 3 of
        0 -> flip rotateR 1
        1 -> flip rotateR 2
        2 -> flip rotateR 3
        _ -> flip rotateR 5
{-# INLINE ror #-}

f5 :: (a -> a) -> a -> a
f5 f = f . f . f . f . f

f6 :: (a -> a) -> a -> a
f6 f = f . f . f . f . f . f


-- Encryption

-- | Encrypts a block using the specified key
encrypt :: Key -> Word64 -> Word64
encrypt k = comp64 . enc k . decomp64

enc :: Key -> Q -> Q
enc k r =
    fst $ f5 (mixingRound k) $ mashingRound k
        $ f6 (mixingRound k) $ mashingRound k
        $ f5 (mixingRound k) (r, 0)

-- Decryption

-- | Decrypts a block using the specified key
decrypt :: Key -> Word64 -> Word64
decrypt k = comp64 . dec k . decomp64

dec :: Key -> Q -> Q
dec k r =
    fst $ f5 (rmixingRound k) $ rmashingRound k
        $ f6 (rmixingRound k) $ rmashingRound k
        $ f5 (rmixingRound k) (r, 63)


-- Encryptiong rounds

mixUp :: Key -> Word8 -> (Q, Int) -> (Q, Int)
mixUp k i input@(r, j) = seq r' $ seq j' (r', j')
  where j' = j + 1
        r' = setR r i (rol i (ri + gmix k i input))
        ri = getR r i
{-# INLINE mixUp #-}

mixingRound :: Key -> (Q, Int) -> (Q, Int)
mixingRound k = mixUp k 3 . mixUp k 2 . mixUp k 1 . mixUp k 0

mash :: Key -> Word8 -> (Q, Int) -> (Q, Int)
mash = gmash (+)
{-# INLINE mash #-}

mashingRound :: Key -> (Q, Int) -> (Q, Int)
mashingRound k = mash k 3 . mash k 2 . mash k 1 . mash k 0


-- Decryption rounds

rmixUp :: Key -> Word8 -> (Q, Int) -> (Q, Int)
rmixUp k i input@(r, j) = seq r' $ seq j' (r', j')
  where j' = j - 1
        r' = setR r i (ri - gmix k i input)
        ri = ror i (getR r i)
{-# INLINE rmixUp #-}

rmixingRound :: Key -> (Q, Int) -> (Q, Int)
rmixingRound k = rmixUp k 0 . rmixUp k 1 . rmixUp k 2 . rmixUp k 3

rmash :: Key -> Word8 -> (Q, Int) -> (Q, Int)
rmash = gmash (-)
{-# INLINE rmash #-}

rmashingRound :: Key -> (Q, Int) -> (Q, Int)
rmashingRound k = rmash k 0 . rmash k 1 . rmash k 2 . rmash k 3


-- Generic rounds

gmix :: Key -> Word8 -> (Q, Int) -> Word16
gmix (Key k) i (r, j) = kj + (ri1 .&. ri2) + (complement ri1 .&. ri3)
  where ri1 = getR r (i - 1)
        ri2 = getR r (i - 2)
        ri3 = getR r (i - 3)
        kj  = unsafeIndex k (Offset j)
{-# INLINE gmix #-}

gmash :: (Word16 -> Word16 -> Word16)
      -> Key -> Word8 -> (Q, Int) -> (Q, Int)
gmash op (Key k) i (r, j) = seq r' $ seq j (r', j)
  where r'  = setR r i (ri `op` kp)
        ri  = getR r i
        ri1 = getR r (i - 1)
        kp  = unsafeIndex k $ Offset (fromIntegral ri1 .&. 63)
{-# INLINE gmash #-}


-- Key expansion

-- | Perform key expansion
buildKey :: ByteArrayAccess key
         => Int    -- ^ Effective key length in bits
         -> key    -- ^ Input key between 1 and 128 bytes
         -> Key    -- ^ Expanded key
buildKey t1 key = Key $ doCast $ B.allocAndFreeze 128 $ \p -> do
    B.copyByteArrayToPtr key p

    forM_ [t .. 127] $ \i -> do
        pos <- (+) <$> peekElemOff p (i - 1) <*> peekElemOff p (i - t)
        let b = unsafeIndex piTable (fromIntegral pos)
        pokeElemOff p i b

    pos' <- (.&. tm) <$> peekElemOff p (128 - t8)
    let b' = unsafeIndex piTable (fromIntegral pos')
    pokeElemOff p (128 - t8) b'

    forM_ (Prelude.reverse [0 .. 127 - t8]) $ \i -> do
        pos <- xor <$> peekElemOff p (i + 1) <*> peekElemOff p (i + t8)
        let b = unsafeIndex piTable (fromIntegral pos)
        pokeElemOff p i b

  where t  = B.length key
        t8 = (t1 + 7) `div` 8
        tm | t1 == 8 * t8 = 255
           | otherwise    = 255 `mod` shiftL 1 (8 + t1 - 8 * t8)

        doCast :: Block Word8 -> Block Word16
        doCast = Basement.Block.map fromLE . cast


-- PITABLE

piTable :: Block Word8
piTable = fromList
    [ 0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d
    , 0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2
    , 0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32
    , 0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82
    , 0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc
    , 0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26
    , 0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03
    , 0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7
    , 0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a
    , 0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec
    , 0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39
    , 0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31
    , 0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9
    , 0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9
    , 0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e
    , 0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad
    ]
