-- |
-- Module      : Crypto.Store.KeyWrap.RC2
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- RC2 Key Wrap (<https://tools.ietf.org/html/rfc3217 RFC 3217>)
--
-- Should be used with a cipher from module "Crypto.Store.Cipher.RC2".
module Crypto.Store.KeyWrap.RC2
    ( wrap
    , wrap'
    , unwrap
    ) where

import           Data.ByteArray (ByteArray)
import qualified Data.ByteArray as B

import Crypto.Cipher.Types
import Crypto.Hash
import Crypto.Random

import Crypto.Store.Util

checksum :: ByteArray ba => ba -> ba
checksum bs = B.convert $ B.takeView (hashWith SHA1 bs) 8

iv4adda22c79e82105 :: B.Bytes
iv4adda22c79e82105 = B.pack [0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05]

-- | Wrap an RC2 key with the specified RC2 cipher.
--
-- Input must be between 0 and 255 bytes.  A fresh IV should be generated
-- randomly for each invocation.
wrap :: (MonadRandom m, BlockCipher cipher, ByteArray ba)
     => cipher -> IV cipher -> ba -> m (Either String ba)
wrap = wrap' (return . Left) randomPad
  where randomPad f = fmap (Right . f) . getRandomBytes

-- | Wrap an RC2 key with the specified RC2 cipher, using the given source of
-- random padding data.
--
-- Input must be between 0 and 255 bytes.  A fresh IV should be generated
-- randomly for each invocation.
wrap' :: (ByteArray ba, BlockCipher cipher)
      => (String -> result) -> ((ba -> ba) -> Int -> result)
      -> cipher -> IV cipher -> ba -> result
wrap' failure withRandomPad cipher iv cek
    | inLen < 256 = withRandomPad f padlen
    | otherwise   =
        failure "KeyWrap.RC2: invalid length for content encryption key"
  where
    inLen      = B.length cek
    padlen     = (7 - inLen) `mod` 8

    f pad =
        let lcek       = B.cons (fromIntegral inLen) cek
            lcekpad    = B.append lcek pad
            lcekpadicv = B.append lcekpad (checksum lcekpad)
            temp1      = cbcEncrypt cipher iv lcekpadicv
            temp2      = B.append (B.convert iv) temp1
            temp3      = reverseBytes temp2
            Just iv'   = makeIV iv4adda22c79e82105
         in cbcEncrypt cipher iv' temp3

-- | Unwrap an encrypted RC2 key with the specified RC2 cipher.
unwrap :: (BlockCipher cipher, ByteArray ba)
       => cipher -> ba -> Either String ba
unwrap cipher wrapped
    | inLen <= 16        = invalid
    | inLen `mod` 8 /= 0 = invalid
    | checksumPadValid   = Right cek
    | otherwise          = invalid
  where
    inLen            = B.length wrapped
    Just iv'         = makeIV iv4adda22c79e82105
    temp3            = cbcDecrypt cipher iv' wrapped
    temp2            = reverseBytes temp3
    (ivBs, temp1)    = B.splitAt 8 temp2
    Just iv          = makeIV ivBs
    lcekpadicv       = cbcDecrypt cipher iv temp1
    (lcekpad, icv)   = B.splitAt (inLen - 16) lcekpadicv
    Just (l, cekpad) = B.uncons lcekpad
    len              = fromIntegral l
    padlen           = inLen - 16 - len - 1
    cek              = B.take len cekpad
    invalid          = Left "KeyWrap.RC2: invalid checksum"
    checksumPadValid = B.constEq icv (checksum lcekpad)
                           &&! padlen >=0 &&! padlen < 8
