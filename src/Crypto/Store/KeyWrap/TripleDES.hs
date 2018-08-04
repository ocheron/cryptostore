-- |
-- Module      : Crypto.Store.KeyWrap.TripleDES
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Triple-DES Key Wrap (<https://tools.ietf.org/html/rfc3217 RFC 3217>)
--
-- Should be used with a cipher from module "Crypto.Cipher.TripleDES".
module Crypto.Store.KeyWrap.TripleDES
    ( wrap
    , unwrap
    ) where

import           Data.ByteArray (ByteArray)
import qualified Data.ByteArray as B

import Crypto.Cipher.Types
import Crypto.Hash

import Crypto.Store.Util

checksum :: ByteArray ba => ba -> ba
checksum bs = B.convert $ B.takeView (hashWith SHA1 bs) 8

iv4adda22c79e82105 :: B.Bytes
iv4adda22c79e82105 = B.pack [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05]

-- | Wrap a Triple-DES key with the specified Triple-DES cipher.
--
-- Input must be 24 bytes.  A fresh IV should be generated randomly for each
-- invocation.
wrap :: (BlockCipher cipher, ByteArray ba)
     => cipher -> IV cipher -> ba -> Either String ba
wrap cipher iv cek
    | inLen == 24 = Right wrapped
    | otherwise   =
        Left "KeyWrap.TripleDES: invalid length for content encryption key"
  where
    inLen    = B.length cek
    Just iv' = makeIV iv4adda22c79e82105
    cekicv   = B.append cek (checksum cek)
    temp1    = cbcEncrypt cipher iv cekicv
    temp2    = B.append (B.convert iv) temp1
    temp3    = reverseBytes temp2
    wrapped  = cbcEncrypt cipher iv' temp3

-- | Unwrap an encrypted Triple-DES key with the specified Triple-DES cipher.
unwrap :: (BlockCipher cipher, ByteArray ba)
       => cipher -> ba -> Either String ba
unwrap cipher wrapped
    | inLen /= 40                  = invalid
    | B.constEq icv (checksum cek) = Right cek
    | otherwise                    = invalid
  where
    inLen         = B.length wrapped
    Just iv'      = makeIV iv4adda22c79e82105
    temp3         = cbcDecrypt cipher iv' wrapped
    temp2         = reverseBytes temp3
    (ivBs, temp1) = B.splitAt 8 temp2
    Just iv       = makeIV ivBs
    cekicv        = cbcDecrypt cipher iv temp1
    (cek, icv)    = B.splitAt 24 cekicv
    invalid       = Left "KeyWrap.TripleDES: invalid checksum"
