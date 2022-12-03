-- |
-- Module      : Data.Store.PKCS5.PBES1
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Password-Based Encryption Schemes
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
module Crypto.Store.PKCS5.PBES1
    ( PBEParameter(..)
    , Key
    , ProtectionPassword
    , emptyNotTerminated
    , fromProtectionPassword
    , toProtectionPassword
    , toProtectionPasswords
    , pkcs5
    , pkcs12
    , pkcs12rc2
    , pkcs12stream
    , pkcs12mac
    , rc4Combine
    ) where

import           Basement.Block (Block)
import           Basement.Compat.IsList
import           Basement.Endianness
import qualified Basement.String as S

import           Crypto.Cipher.Types
import qualified Crypto.Cipher.RC4 as RC4
import qualified Crypto.Hash as Hash

import           Data.ASN1.Types
import           Data.Bits
import           Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteArray as B
import           Data.ByteString (ByteString)
import           Data.Maybe (fromMaybe)
import           Data.Memory.PtrMethods
import           Data.String (IsString(..))
import           Data.Word

import           Foreign.Ptr (plusPtr)
import           Foreign.Storable

import Crypto.Store.ASN1.Parse
import Crypto.Store.ASN1.Generate
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Util
import Crypto.Store.Error

-- | A password stored as a sequence of UTF-8 bytes.
--
-- Some key-derivation functions add restrictions to what characters
-- are supported.
--
-- The data type provides a special value 'emptyNotTerminated' that is used
-- as alternate representation of empty passwords on some systems and that
-- produces encryption results different than an empty bytearray.
--
-- Conversion to/from a regular sequence of bytes is possible with functions
-- 'toProtectionPassword' and 'fromProtectionPassword'.
--
-- Beware: the 'fromString' implementation correctly handles multi-byte
-- characters, so here is not equivalent to the 'ByteString' counterpart.
data ProtectionPassword = NullPassword | PasswordUTF8 ByteString
    deriving Eq

instance Show ProtectionPassword where
    showsPrec _ NullPassword     = showString "emptyNotTerminated"
    showsPrec d (PasswordUTF8 b) = showParen (d > 10) $
        showString "toProtectionPassword " . showsPrec 11 b

instance IsString ProtectionPassword where
    fromString = PasswordUTF8 . B.convert . S.toBytes S.UTF8 . fromString

instance ByteArrayAccess ProtectionPassword where
    length = applyPP 0 B.length
    withByteArray = B.withByteArray . fromProtectionPassword

applyPP :: a -> (ByteString -> a) -> ProtectionPassword -> a
applyPP d _ NullPassword     = d
applyPP _ f (PasswordUTF8 b) = f b

-- | A value denoting an empty password, but having a special encoding when
-- deriving a symmetric key on some systems, like the certificate export
-- wizard on Windows.
--
-- This value is different from @'toProtectionPassword ""'@ and can be tried
-- when decrypting content with a password known to be empty.
emptyNotTerminated :: ProtectionPassword
emptyNotTerminated = NullPassword

-- | Extract the UTF-8 bytes in a password value.
fromProtectionPassword :: ProtectionPassword -> ByteString
fromProtectionPassword = applyPP B.empty id

-- | Build a password value from a sequence of UTF-8 bytes.
--
-- When the password is empty, the special value 'emptyNotTerminated' may
-- be tried as well.
toProtectionPassword :: ByteString -> ProtectionPassword
toProtectionPassword = PasswordUTF8

toProtectionPasswords :: ByteString -> [ProtectionPassword]
toProtectionPasswords bs
    | B.null bs = [PasswordUTF8 B.empty, NullPassword]
    | otherwise = [PasswordUTF8 bs]

-- | Secret key.
type Key = B.ScrubbedBytes

-- | PBES1 parameters.
data PBEParameter = PBEParameter
    { pbeSalt           :: Salt -- ^ 8-octet salt value
    , pbeIterationCount :: Int  -- ^ Iteration count
    }
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e PBEParameter where
    asn1s PBEParameter{..} =
        let salt  = gOctetString pbeSalt
            iters = gIntVal (toInteger pbeIterationCount)
         in asn1Container Sequence (salt . iters)

instance Monoid e => ParseASN1Object e PBEParameter where
    parse = onNextContainer Sequence $ do
        OctetString salt <- getNext
        IntVal iters <- getNext
        return PBEParameter { pbeSalt = salt
                            , pbeIterationCount = fromInteger iters }

cbcWith :: (BlockCipher cipher, ByteArrayAccess iv)
        => ContentEncryptionCipher cipher -> iv -> ContentEncryptionParams
cbcWith cipher iv = ParamsCBC cipher getIV
  where
    getIV = fromMaybe (error "PKCS5: bad initialization vector") (makeIV iv)

rc2cbcWith :: ByteArrayAccess iv => Int -> iv -> ContentEncryptionParams
rc2cbcWith len iv = ParamsCBCRC2 len getIV
  where
    getIV = fromMaybe (error "PKCS5: bad RC2 initialization vector") (makeIV iv)

-- | RC4 encryption or decryption.
rc4Combine :: (ByteArrayAccess key, ByteArray ba) => key -> ba -> Either StoreError ba
rc4Combine key = Right . snd . RC4.combine (RC4.initialize key)

-- | Conversion to UCS2 from UTF-8, ignoring non-BMP bits.
toUCS2 :: ByteArray bucs2 => ProtectionPassword -> Maybe bucs2
toUCS2 NullPassword = Just B.empty
toUCS2 (PasswordUTF8 pwdUTF8)
    | B.null r  = Just pwdUCS2
    | otherwise = Nothing
  where
    (p, _, r) = S.fromBytes S.UTF8 $ B.snoc (B.convert pwdUTF8) 0
    pwdBlock  = fromList $ map ucs2 $ toList p :: Block (BE Word16)
    pwdUCS2   = B.convert pwdBlock

    ucs2 :: Char -> BE Word16
    ucs2 = toBE . toEnum . fromEnum


-- PBES1, RFC 8018 section 6.1.2

-- | Apply PBKDF1 on the specified password and run an encryption or decryption
-- function on some input using derived key and IV.
pkcs5 :: (Hash.HashAlgorithm hash, BlockCipher cipher)
      => (StoreError -> result)
      -> (Key -> ContentEncryptionParams -> ByteString -> result)
      -> DigestProxy hash
      -> ContentEncryptionCipher cipher
      -> PBEParameter
      -> ByteString
      -> ProtectionPassword
      -> result
pkcs5 failure encdec hashAlg cec pbeParam bs pwd
    | proxyBlockSize cec /= 8 = failure (InvalidParameter "Invalid cipher block size")
    | otherwise =
        case pbkdf1 hashAlg (fromProtectionPassword pwd) pbeParam 16 of
            Left err -> failure err
            Right dk ->
                let (key, iv) = B.splitAt 8 (dk :: Key)
                 in encdec key (cbcWith cec iv) bs


-- PBKDF1, RFC 8018 section 5.1

pbkdf1 :: (Hash.HashAlgorithm hash, ByteArrayAccess password, ByteArray out)
       => DigestProxy hash
       -> password
       -> PBEParameter
       -> Int
       -> Either StoreError out
pbkdf1 hashAlg pwd PBEParameter{..} dkLen
    | dkLen > B.length t1 = Left (InvalidParameter "Derived key too long")
    | otherwise           = Right (B.convert $ B.takeView tc dkLen)
  where
    a  = hashFromProxy hashAlg
    t1 = Hash.hashFinalize (Hash.hashUpdate (Hash.hashUpdate (Hash.hashInitWith a) pwd) pbeSalt)
    tc = iterate (Hash.hashWith a) t1 !! pred pbeIterationCount


-- PKCS#12 encryption, RFC 7292 appendix B.2

-- | Apply PKCS #12 derivation on the specified password and run an encryption
-- or decryption function on some input using derived key and IV.
pkcs12 :: (Hash.HashAlgorithm hash, BlockCipher cipher)
       => (StoreError -> result)
       -> (Key -> ContentEncryptionParams -> ByteString -> result)
       -> DigestProxy hash
       -> ContentEncryptionCipher cipher
       -> PBEParameter
       -> ByteString
       -> ProtectionPassword
       -> result
pkcs12 failure encdec hashAlg cec pbeParam bs pwdUTF8 =
    case toUCS2 pwdUTF8 of
        Nothing      -> failure passwordNotUTF8
        Just pwdUCS2 ->
            let ivLen   = proxyBlockSize cec
                iv      = pkcs12Derive hashAlg pbeParam 2 pwdUCS2 ivLen :: B.Bytes
                eScheme = cbcWith cec iv
                keyLen  = getMaximumKeySize eScheme
                key     = pkcs12Derive hashAlg pbeParam 1 pwdUCS2 keyLen :: Key
            in encdec key eScheme bs

-- | Apply PKCS #12 derivation on the specified password and run an encryption
-- or decryption function on some input using derived key and IV.  This variant
-- uses an RC2 cipher with the EKL specified (effective key length).
pkcs12rc2 :: Hash.HashAlgorithm hash
          => (StoreError -> result)
          -> (Key -> ContentEncryptionParams -> ByteString -> result)
          -> DigestProxy hash
          -> Int
          -> PBEParameter
          -> ByteString
          -> ProtectionPassword
          -> result
pkcs12rc2 failure encdec hashAlg len pbeParam bs pwdUTF8 =
    case toUCS2 pwdUTF8 of
        Nothing      -> failure passwordNotUTF8
        Just pwdUCS2 ->
            let ivLen   = 8
                iv      = pkcs12Derive hashAlg pbeParam 2 pwdUCS2 ivLen :: B.Bytes
                eScheme = rc2cbcWith len iv
                keyLen  = getMaximumKeySize eScheme
                key     = pkcs12Derive hashAlg pbeParam 1 pwdUCS2 keyLen :: Key
            in encdec key eScheme bs

-- | Apply PKCS #12 derivation on the specified password and run an encryption
-- or decryption function on some input using derived key.  This variant does
-- not derive any IV and is required for RC4.
pkcs12stream :: Hash.HashAlgorithm hash
             => (StoreError -> result)
             -> (Key -> ByteString -> result)
             -> DigestProxy hash
             -> Int
             -> PBEParameter
             -> ByteString
             -> ProtectionPassword
             -> result
pkcs12stream failure encdec hashAlg keyLen pbeParam bs pwdUTF8 =
    case toUCS2 pwdUTF8 of
        Nothing      -> failure passwordNotUTF8
        Just pwdUCS2 ->
            let key = pkcs12Derive hashAlg pbeParam 1 pwdUCS2 keyLen :: Key
             in encdec key bs

-- | Apply PKCS #12 derivation on the specified password and run a MAC function
-- on some input using derived key.
pkcs12mac :: Hash.HashAlgorithm hash
          => (StoreError -> result)
          -> (Key -> MACAlgorithm -> ByteString -> result)
          -> DigestProxy hash
          -> PBEParameter
          -> ByteString
          -> ProtectionPassword
          -> result
pkcs12mac failure macFn hashAlg pbeParam bs pwdUTF8 =
    case toUCS2 pwdUTF8 of
        Nothing      -> failure passwordNotUTF8
        Just pwdUCS2 ->
            let macAlg = HMAC hashAlg
                keyLen = getMaximumKeySize macAlg
                key    = pkcs12Derive hashAlg pbeParam 3 pwdUCS2 keyLen :: Key
            in macFn key macAlg bs

passwordNotUTF8 :: StoreError
passwordNotUTF8 = InvalidPassword "Provided password is not valid UTF-8"

pkcs12Derive :: (Hash.HashAlgorithm hash, ByteArray bout)
             => DigestProxy hash
             -> PBEParameter
             -> Word8
             -> ByteString -- password (UCS2)
             -> Int
             -> bout
pkcs12Derive hashAlg PBEParameter{..} idByte pwdUCS2 n =
    B.take n $ B.concat $ take c $ loop t (s `B.append` p)
  where
    a = hashFromProxy hashAlg
    v = getV (DigestAlgorithm hashAlg)
    u = Hash.hashDigestSize a

    c = (n + u - 1) `div` u
    d = B.replicate v idByte :: B.Bytes
    t = Hash.hashUpdate (Hash.hashInitWith a) d

    p = pwdUCS2 `extendedToMult` v
    s = pbeSalt `extendedToMult` v

    loop :: Hash.HashAlgorithm hash
         => Hash.Context hash -> ByteString -> [Hash.Digest hash]
    loop x i = let z  = Hash.hashFinalize (Hash.hashUpdate x i)
                   ai = iterate Hash.hash z !! pred pbeIterationCount
                   b  = ai `extendedTo` v
                   j  = B.concat $ map (add1 b) (chunks v i)
                in ai : loop x j

getV :: DigestAlgorithm -> Int
getV (DigestAlgorithm MD2)    = 64
getV (DigestAlgorithm MD4)    = 64
getV (DigestAlgorithm MD5)    = 64
getV (DigestAlgorithm SHA1)   = 64
getV (DigestAlgorithm SHA224) = 64
getV (DigestAlgorithm SHA256) = 64
getV (DigestAlgorithm SHA384) = 128
getV (DigestAlgorithm SHA512) = 128
getV t                        = error ("pkcs12Derive: unsupported hash: " ++ show t)

hashFromProxy :: proxy a -> a
hashFromProxy _ = undefined

-- Split in chunks of size 'n'
chunks :: ByteArray ba => Int -> ba -> [ba]
chunks n bs
    | len > n   = let (c, cs) = B.splitAt n bs in c : chunks n cs
    | len > 0   = [bs]
    | otherwise = []
  where
    len = B.length bs

-- Concatenate copies of input 'bs' to create output of length 'n'
-- bytes (the final copy may be truncated)
extendedTo :: (ByteArrayAccess bin, ByteArray bout) => bin -> Int -> bout
bs `extendedTo` n =
    B.allocAndFreeze n $ \pout ->
        B.withByteArray bs $ \pin -> do
            mapM_ (\off -> memCopy (pout `plusPtr` off) pin len)
                  (enumFromThenTo 0 len (n - len))
            memCopy (pout `plusPtr` (n - r)) pin r
  where
    len = B.length bs
    r   = n `mod` len
{-# NOINLINE extendedTo #-}

-- Concatenate copies of input 'bs' to create output whose length is a
-- multiple of 'n' bytes (the final copy may be truncated).  If input
-- is the empty string, so is the output.
extendedToMult :: ByteArray ba => ba -> Int -> ba
bs `extendedToMult` n
    | len > n   = bs `B.append` B.take (n - len `mod` n) bs
    | len == n  = bs
    | len > 0   = bs `extendedTo` n
    | otherwise = B.empty
  where
    len = B.length bs

-- Add two bytearrays (considered as big-endian integers) and increment the
-- result.  Output has size of the first bytearray.
add1 :: ByteString -> ByteString -> ByteString
add1 a b =
    B.allocAndFreeze alen $ \pc ->
        B.withByteArray a $ \pa ->
        B.withByteArray b $ \pb ->
            loop3 pa pb pc alen blen 1
  where
    alen = B.length a
    blen = B.length b

    -- main loop when both 'a' and 'b' have remaining bytes
    loop3 !pa !pb !pc !ma !mb !c
        | ma == 0   = return ()
        | mb == 0   = loop2 pa pc ma c
        | otherwise = do
            let na = pred ma
                nb = pred mb
            ba <- peekElemOff pa na
            bb <- peekElemOff pb nb
            let (cc, bc) = carryAdd3 c ba bb
            pokeElemOff pc na bc
            loop3 pa pb pc na nb cc

    -- when 'b' is smaller and bytes are exhausted we propagate
    -- carry on 'a' alone
    loop2 !pa !pc !ma !c
        | ma == 0   = return ()
        | otherwise = do
            let na = pred ma
            ba <- peekElemOff pa na
            let (cc, bc) = carryAdd2 c ba
            pokeElemOff pc na bc
            loop2 pa pc na cc

split16 :: Word16 -> (Word8, Word8)
split16 x = (fromIntegral (shiftR x 8), fromIntegral x)

carryAdd2 :: Word8 -> Word8 -> (Word8, Word8)
carryAdd2 a b = split16 (fromIntegral a + fromIntegral b)

carryAdd3 :: Word8 -> Word8 -> Word8 -> (Word8, Word8)
carryAdd3 a b c = split16 (fromIntegral a + fromIntegral b + fromIntegral c)
