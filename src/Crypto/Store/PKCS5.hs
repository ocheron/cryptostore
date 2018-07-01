-- |
-- Module      : Data.Store.PKCS5
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Password-Based Cryptography, aka PKCS #5.
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.Store.PKCS5
    ( Password
    , EncryptedContent
    -- * High-level API
    , PKCS5(..)
    , encrypt
    , decrypt
    -- * Encryption schemes
    , EncryptionScheme(..)
    , PBEParameter(..)
    , PBES2Parameter(..)
    -- * Key derivation
    , KeyDerivationFunc(..)
    , PBKDF2_PRF(..)
    , Salt
    , generateSalt
    -- * Content encryption
    , ContentEncryptionParams
    , ContentEncryptionAlg(..)
    , ContentEncryptionCipher(..)
    , generateEncryptionParams
    , getContentEncryptionAlg
    -- * Low-level API
    , pbEncrypt
    , pbDecrypt
    ) where

import           Basement.Block (Block)
import           Basement.Compat.IsList
import           Basement.Endianness
import qualified Basement.String as S

import           Crypto.Cipher.Types
import qualified Crypto.Hash as Hash
import           Crypto.Number.Serialize (i2ospOf_, os2ip)

import           Data.ASN1.Types
import           Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteArray as B
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Maybe (fromMaybe)
import           Data.Memory.PtrMethods
import           Data.Word

import           Foreign.Ptr (plusPtr)

import Crypto.Store.ASN1.Parse
import Crypto.Store.ASN1.Generate
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Encrypted
import Crypto.Store.CMS.Enveloped
import Crypto.Store.CMS.Util

type Key = B.ScrubbedBytes

data EncryptionSchemeType = Type_PBES2
                          | Type_PBE_MD5_DES_CBC
                          | Type_PBE_SHA1_DES_CBC
                          | Type_PBE_SHA1_DES_EDE3_CBC
                          | Type_PBE_SHA1_DES_EDE2_CBC

instance Enumerable EncryptionSchemeType where
    values = [ Type_PBES2
             , Type_PBE_MD5_DES_CBC
             , Type_PBE_SHA1_DES_CBC
             , Type_PBE_SHA1_DES_EDE3_CBC
             , Type_PBE_SHA1_DES_EDE2_CBC
             ]

instance OIDable EncryptionSchemeType where
    getObjectID Type_PBES2                 = [1,2,840,113549,1,5,13]
    getObjectID Type_PBE_MD5_DES_CBC       = [1,2,840,113549,1,5,3]
    getObjectID Type_PBE_SHA1_DES_CBC      = [1,2,840,113549,1,5,10]
    getObjectID Type_PBE_SHA1_DES_EDE3_CBC = [1,2,840,113549,1,12,1,3]
    getObjectID Type_PBE_SHA1_DES_EDE2_CBC = [1,2,840,113549,1,12,1,4]

instance OIDNameable EncryptionSchemeType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

-- | Password-Based Encryption Scheme (PBES).
data EncryptionScheme = PBES2 PBES2Parameter               -- ^ PBES2
                      | PBE_MD5_DES_CBC PBEParameter       -- ^ pbeWithMD5AndDES-CBC
                      | PBE_SHA1_DES_CBC PBEParameter      -- ^ pbeWithSHA1AndDES-CBC
                      | PBE_SHA1_DES_EDE3_CBC PBEParameter -- ^ pbeWithSHAAnd3-KeyTripleDES-CBC
                      | PBE_SHA1_DES_EDE2_CBC PBEParameter -- ^ pbeWithSHAAnd2-KeyTripleDES-CBC
                      deriving (Show,Eq)

-- | PBES1 parameters.
data PBEParameter = PBEParameter
    { pbeSalt           :: Salt -- ^ 8-octet salt value
    , pbeIterationCount :: Int  -- ^ Iteration count
    }
    deriving (Show,Eq)

instance ParseASN1Object PBEParameter where
    asn1s PBEParameter{..} =
        let salt  = gOctetString pbeSalt
            iters = gIntVal (toInteger pbeIterationCount)
         in asn1Container Sequence (salt . iters)

    parse = onNextContainer Sequence $ do
        OctetString salt <- getNext
        IntVal iters <- getNext
        return PBEParameter { pbeSalt = salt
                            , pbeIterationCount = fromInteger iters }

-- | PBES2 parameters.
data PBES2Parameter = PBES2Parameter
    { pbes2KDF     :: KeyDerivationFunc       -- ^ Key derivation function
    , pbes2EScheme :: ContentEncryptionParams -- ^ Underlying encryption scheme
    }
    deriving (Show,Eq)

instance ParseASN1Object PBES2Parameter where
    asn1s PBES2Parameter{..} =
        let kdFunc  = algorithmASN1S Sequence pbes2KDF
            eScheme = asn1s pbes2EScheme
         in asn1Container Sequence (kdFunc . eScheme)

    parse = onNextContainer Sequence $ do
        kdFunc  <- parseAlgorithm Sequence
        eScheme <- parse
        case kdfKeyLength kdFunc of
            Nothing -> return ()
            Just sz
                | validateKeySize eScheme sz -> return ()
                | otherwise -> throwParseError "PBES2Parameter: parsed key length incompatible with encryption scheme"
        return PBES2Parameter { pbes2KDF = kdFunc, pbes2EScheme = eScheme }

instance AlgorithmId EncryptionScheme where
    type AlgorithmType EncryptionScheme = EncryptionSchemeType
    algorithmName _  = "encryption scheme"

    algorithmType (PBES2 _)                 = Type_PBES2
    algorithmType (PBE_MD5_DES_CBC _)       = Type_PBE_MD5_DES_CBC
    algorithmType (PBE_SHA1_DES_CBC _)      = Type_PBE_SHA1_DES_CBC
    algorithmType (PBE_SHA1_DES_EDE3_CBC _) = Type_PBE_SHA1_DES_EDE3_CBC
    algorithmType (PBE_SHA1_DES_EDE2_CBC _) = Type_PBE_SHA1_DES_EDE2_CBC

    parameterASN1S (PBES2 p)                 = asn1s p
    parameterASN1S (PBE_MD5_DES_CBC p)       = asn1s p
    parameterASN1S (PBE_SHA1_DES_CBC p)      = asn1s p
    parameterASN1S (PBE_SHA1_DES_EDE3_CBC p) = asn1s p
    parameterASN1S (PBE_SHA1_DES_EDE2_CBC p) = asn1s p

    parseParameter Type_PBES2                 = PBES2 <$> parse
    parseParameter Type_PBE_MD5_DES_CBC       = PBE_MD5_DES_CBC <$> parse
    parseParameter Type_PBE_SHA1_DES_CBC      = PBE_SHA1_DES_CBC <$> parse
    parseParameter Type_PBE_SHA1_DES_EDE3_CBC = PBE_SHA1_DES_EDE3_CBC <$> parse
    parseParameter Type_PBE_SHA1_DES_EDE2_CBC = PBE_SHA1_DES_EDE2_CBC <$> parse


-- High-level API

-- | Content encrypted with a Password-Based Encryption Scheme (PBES).
--
-- The content will usually be the binary representation of an ASN.1 object,
-- however the transformation may be applied to any bytestring.
data PKCS5 = PKCS5
    { encryptionAlgorithm :: EncryptionScheme -- ^ Scheme used to encrypt content
    , encryptedData       :: EncryptedContent -- ^ Encrypted content
    }
    deriving (Show,Eq)

instance ParseASN1Object PKCS5 where
    asn1s PKCS5{..} = asn1Container Sequence (alg . bs)
      where alg = algorithmASN1S Sequence encryptionAlgorithm
            bs  = gOctetString encryptedData

    parse = onNextContainer Sequence $ do
        alg <- parseAlgorithm Sequence
        OctetString bs <- getNext
        return PKCS5 { encryptionAlgorithm = alg, encryptedData = bs }

instance ASN1Object PKCS5 where
    toASN1   = asn1s
    fromASN1 = runParseASN1State parse

-- | Encrypt a bytestring with the specified encryption scheme and password.
encrypt :: EncryptionScheme -> Password -> ByteString -> Either String PKCS5
encrypt alg pwd bs = build <$> pbEncrypt alg bs pwd
  where
    build ed = ed `seq` PKCS5 { encryptionAlgorithm = alg, encryptedData = ed }

-- | Decrypt the PKCS #5 content with the specified password.
decrypt :: PKCS5 -> Password -> Either String ByteString
decrypt obj = pbDecrypt (encryptionAlgorithm obj) (encryptedData obj)


-- Encryption Schemes

-- | Encrypt a bytestring with the specified encryption scheme and password.
pbEncrypt :: EncryptionScheme -> ByteString -> Password
          -> Either String EncryptedContent
pbEncrypt (PBES2 p)                 = pbes2  contentEncrypt p
pbEncrypt (PBE_MD5_DES_CBC p)       = pkcs5  Left contentEncrypt Hash.MD5  DES p
pbEncrypt (PBE_SHA1_DES_CBC p)      = pkcs5  Left contentEncrypt Hash.SHA1 DES p
pbEncrypt (PBE_SHA1_DES_EDE3_CBC p) = pkcs12 Left contentEncrypt Hash.SHA1 DES_EDE3 p
pbEncrypt (PBE_SHA1_DES_EDE2_CBC p) = pkcs12 Left contentEncrypt Hash.SHA1 DES_EDE2 p

-- | Decrypt an encrypted bytestring with the specified encryption scheme and
-- password.
pbDecrypt :: EncryptionScheme -> EncryptedContent -> Password -> Either String ByteString
pbDecrypt (PBES2 p)                 = pbes2  contentDecrypt p
pbDecrypt (PBE_MD5_DES_CBC p)       = pkcs5  Left contentDecrypt Hash.MD5  DES p
pbDecrypt (PBE_SHA1_DES_CBC p)      = pkcs5  Left contentDecrypt Hash.SHA1 DES p
pbDecrypt (PBE_SHA1_DES_EDE3_CBC p) = pkcs12 Left contentDecrypt Hash.SHA1 DES_EDE3 p
pbDecrypt (PBE_SHA1_DES_EDE2_CBC p) = pkcs12 Left contentDecrypt Hash.SHA1 DES_EDE2 p

pbes2 :: ByteArrayAccess password
      => (Key -> ContentEncryptionParams -> ByteString -> result)
      -> PBES2Parameter -> ByteString -> password -> result
pbes2 encdec PBES2Parameter{..} bs pwd = encdec key pbes2EScheme bs
  where key = kdfDerive pbes2KDF len pwd :: Key
        len = fromMaybe (getMaximumKeySize pbes2EScheme) (kdfKeyLength pbes2KDF)

cbcWith :: (BlockCipher cipher, ByteArrayAccess iv)
        => ContentEncryptionCipher cipher -> iv -> ContentEncryptionParams
cbcWith cipher iv = ParamsCBC cipher getIV
  where
    getIV = fromMaybe (error "PKCS5: bad initialization vector") (makeIV iv)


-- PBES1, RFC 8018 section 6.1.2

pkcs5 :: (Hash.HashAlgorithm hash, BlockCipher cipher, ByteArrayAccess password)
      => (String -> result)
      -> (Key -> ContentEncryptionParams -> ByteString -> result)
      -> hash
      -> ContentEncryptionCipher cipher
      -> PBEParameter
      -> ByteString
      -> password
      -> result
pkcs5 failure encdec hashAlg cec pbeParam bs pwd
    | proxyBlockSize cec /= 8 = failure "PKCS5: invalid cipher block size"
    | otherwise =
        case pbkdf1 hashAlg pwd pbeParam 16 of
            Left err -> failure err
            Right dk ->
                let (key, iv) = B.splitAt 8 (dk :: Key)
                 in encdec key (cbcWith cec iv) bs


-- PBKDF1, RFC 8018 section 5.1

pbkdf1 :: (Hash.HashAlgorithm hash, ByteArrayAccess password, ByteArray out)
       => hash
       -> password
       -> PBEParameter
       -> Int
       -> Either String out
pbkdf1 hashAlg pwd PBEParameter{..} dkLen
    | dkLen > B.length t1 = Left "PBKDF1: derived key too long"
    | otherwise           = Right (B.convert $ B.takeView tc dkLen)
  where
    t1 = Hash.hashFinalize (Hash.hashUpdate (Hash.hashUpdate (Hash.hashInitWith hashAlg) pwd) pbeSalt)
    tc = iterate (Hash.hashWith hashAlg) t1 !! pred pbeIterationCount


-- PKCS#12 encryption, RFC 7292 appendix B.2

pkcs12 :: (Hash.HashAlgorithm hash, BlockCipher cipher, ByteArrayAccess password)
       => (String -> result)
       -> (Key -> ContentEncryptionParams -> ByteString -> result)
       -> hash
       -> ContentEncryptionCipher cipher
       -> PBEParameter
       -> ByteString
       -> password
       -> result
pkcs12 failure encdec hashAlg cec pbeParam bs pwdUTF8
    | B.null r  = encdec key eScheme bs
    | otherwise = failure "Provided password is not valid UTF-8"
  where
    ivLen   = proxyBlockSize cec
    iv      = pkcs12Derive hashAlg pbeParam 2 pwdUCS2 ivLen :: B.Bytes
    eScheme = cbcWith cec iv
    keyLen  = getMaximumKeySize eScheme
    key     = pkcs12Derive hashAlg pbeParam 1 pwdUCS2 keyLen :: B.ScrubbedBytes

    -- conversion to UCS2 from UTF-8, ignoring non-BMP bits
    (p, _, r) = S.fromBytes S.UTF8 $ B.snoc (B.convert pwdUTF8) 0
    pwdBlock  = fromList $ map ucs2 $ toList p :: Block (BE Word16)
    pwdUCS2   = B.convert pwdBlock

    ucs2 :: Char -> BE Word16
    ucs2 = toBE . toEnum . fromEnum

pkcs12Derive :: (Hash.HashAlgorithm hash, ByteArray bout)
             => hash
             -> PBEParameter
             -> Word8
             -> ByteString -- password (UCS2)
             -> Int
             -> bout
pkcs12Derive hashAlg PBEParameter{..} idByte pwdUCS2 n =
    B.take n $ B.concat $ take c $ loop hashAlg (s `B.append` p)
  where
    v = 64 -- always 512 bits, we're using only SHA1
    u = Hash.hashDigestSize hashAlg

    c = (n + u - 1) `div` u
    d = B.replicate v idByte :: B.Bytes

    p = pwdUCS2 `extendedToMult` v
    s = pbeSalt `extendedToMult` v

    add1 :: ByteString -> ByteString -> ByteString
    x `add1` y = BS.tail $ i2ospOf_ (v + 1) (os2ip x + os2ip y + 1)

    loop :: Hash.HashAlgorithm hash => hash -> ByteString -> [Hash.Digest hash]
    loop h i = let z  = Hash.hashFinalize (Hash.hashUpdate (Hash.hashUpdate (Hash.hashInitWith h) d) i)
                   ai = iterate (Hash.hashWith h) z !! pred pbeIterationCount
                   b  = ai `extendedTo` v
                   j  = B.concat $ map (add1 b) (chunks v i)
                in ai : loop h j

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
                  (enumFromThenTo 0 len (n - 1))
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
