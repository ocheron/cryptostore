-- |
-- Module      : Crypto.Store.Cipher.RC2
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : stable
-- Portability : good
--
-- Implementation of RC2 block cipher, a legacy algorithm providing weak
-- security.  Use only for compatibility with software requiring this cipher and
-- data which is not sensitive.
module Crypto.Store.Cipher.RC2
    ( RC2
    , rc2WithEffectiveKeyLength
    ) where

import           Data.ByteArray (ByteArrayAccess)
import qualified Data.ByteArray as B
import qualified Data.ByteArray.Mapping as B
import           Data.Maybe (fromMaybe)

import  Crypto.Error
import  Crypto.Cipher.Types

import  Crypto.Store.Cipher.RC2.Primitive

-- | RC2 block cipher.  Key is between 8 and 1024 bits.
newtype RC2 = RC2 Key

instance Cipher RC2 where
    cipherName    _ = "RC2"
    cipherKeySize _ = KeySizeRange 1 128
    cipherInit      = fmap RC2 . initRC2 Nothing

instance BlockCipher RC2 where
    blockSize _ = 8
    ecbEncrypt (RC2 k) = B.mapAsWord64 (encrypt k)
    ecbDecrypt (RC2 k) = B.mapAsWord64 (decrypt k)

-- | Build a RC2 cipher with the specified effective key length (in bits).
rc2WithEffectiveKeyLength :: ByteArrayAccess key
                          => Int -> key -> CryptoFailable RC2
rc2WithEffectiveKeyLength bits key
    | bits < 1    = CryptoFailed CryptoError_KeySizeInvalid
    | bits > 1024 = CryptoFailed CryptoError_KeySizeInvalid
    | otherwise   = RC2 <$> initRC2 (Just bits) key

initRC2 :: ByteArrayAccess key => Maybe Int -> key -> CryptoFailable Key
initRC2 mbits bs
    | len <    1 = CryptoFailed CryptoError_KeySizeInvalid
    | len <= 128 = CryptoPassed (buildKey t1 bs)
    | otherwise  = CryptoFailed CryptoError_KeySizeInvalid
  where len = B.length bs
        t1  = fromMaybe (8 * len) mbits
