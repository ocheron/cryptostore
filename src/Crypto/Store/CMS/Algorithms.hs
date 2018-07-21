-- |
-- Module      : Crypto.Store.CMS.Algorithms
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Cryptographic Message Syntax algorithms
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.Store.CMS.Algorithms
    ( DigestType(..)
    , DigestAlgorithm(..)
    , digest
    , MessageAuthenticationCode
    , MACAlgorithm(..)
    , mac
    , HasKeySize(..)
    , getMaximumKeySize
    , validateKeySize
    , generateKey
    , ContentEncryptionCipher(..)
    , ContentEncryptionAlg(..)
    , ContentEncryptionParams(..)
    , generateEncryptionParams
    , getContentEncryptionAlg
    , proxyBlockSize
    , contentEncrypt
    , contentDecrypt
    , AuthContentEncryptionAlg(..)
    , AuthContentEncryptionParams(..)
    , generateAuthEnc128Params
    , generateAuthEnc256Params
    , generateChaChaPoly1305Params
    , generateCCMParams
    , generateGCMParams
    , getAuthContentEncryptionAlg
    , authContentEncrypt
    , authContentDecrypt
    , PBKDF2_PRF(..)
    , prf
    , Salt
    , generateSalt
    , KeyDerivationFunc(..)
    , kdfKeyLength
    , kdfDerive
    , KeyEncryptionParams(..)
    , keyEncrypt
    , keyDecrypt
    ) where

import Control.Monad (when)

import           Data.ASN1.OID
import           Data.ASN1.Types
import           Data.Bits
import           Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteArray as B
import           Data.ByteString (ByteString)
import           Data.Maybe (fromMaybe)
import           Data.Word

import qualified Crypto.Cipher.AES as Cipher
import qualified Crypto.Cipher.CAST5 as Cipher
import qualified Crypto.Cipher.Camellia as Cipher
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaChaPoly1305
import qualified Crypto.Cipher.DES as Cipher
import qualified Crypto.Cipher.TripleDES as Cipher
import           Crypto.Cipher.Types
import           Crypto.Data.Padding
import           Crypto.Error
import qualified Crypto.Hash as Hash
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import qualified Crypto.KDF.Scrypt as Scrypt
import qualified Crypto.MAC.HMAC as HMAC
import qualified Crypto.MAC.Poly1305 as Poly1305
import           Crypto.Random

import           Crypto.Store.ASN1.Generate
import           Crypto.Store.ASN1.Parse
import           Crypto.Store.CMS.Util
import qualified Crypto.Store.KeyWrap.AES as AES_KW
import qualified Crypto.Store.KeyWrap.TripleDES as TripleDES_KW


-- Hash functions

-- | CMS digest algorithm.
data DigestAlgorithm hashAlg where
    -- | MD2
    MD2    :: DigestAlgorithm Hash.MD2
    -- | MD4
    MD4    :: DigestAlgorithm Hash.MD4
    -- | MD5
    MD5    :: DigestAlgorithm Hash.MD5
    -- | SHA-1
    SHA1   :: DigestAlgorithm Hash.SHA1
    -- | SHA-224
    SHA224 :: DigestAlgorithm Hash.SHA224
    -- | SHA-256
    SHA256 :: DigestAlgorithm Hash.SHA256
    -- | SHA-384
    SHA384 :: DigestAlgorithm Hash.SHA384
    -- | SHA-512
    SHA512 :: DigestAlgorithm Hash.SHA512

deriving instance Show (DigestAlgorithm hashAlg)
deriving instance Eq (DigestAlgorithm hashAlg)

-- | Existential CMS digest algorithm.
data DigestType =
    forall hashAlg . Hash.HashAlgorithm hashAlg
        => DigestType (DigestAlgorithm hashAlg)

instance Show DigestType where
    show (DigestType a) = show a

instance Eq DigestType where
    DigestType MD2    == DigestType MD2    = True
    DigestType MD4    == DigestType MD4    = True
    DigestType MD5    == DigestType MD5    = True
    DigestType SHA1   == DigestType SHA1   = True
    DigestType SHA224 == DigestType SHA224 = True
    DigestType SHA256 == DigestType SHA256 = True
    DigestType SHA384 == DigestType SHA384 = True
    DigestType SHA512 == DigestType SHA512 = True
    _                 == _                 = False

instance Enumerable DigestType where
    values = [ DigestType MD2
             , DigestType MD4
             , DigestType MD5
             , DigestType SHA1
             , DigestType SHA224
             , DigestType SHA256
             , DigestType SHA384
             , DigestType SHA512
             ]

instance OIDable DigestType where
    getObjectID (DigestType MD2)    = [1,2,840,113549,2,2]
    getObjectID (DigestType MD4)    = [1,2,840,113549,2,4]
    getObjectID (DigestType MD5)    = [1,2,840,113549,2,5]
    getObjectID (DigestType SHA1)   = [1,3,14,3,2,26]
    getObjectID (DigestType SHA224) = [2,16,840,1,101,3,4,2,4]
    getObjectID (DigestType SHA256) = [2,16,840,1,101,3,4,2,1]
    getObjectID (DigestType SHA384) = [2,16,840,1,101,3,4,2,2]
    getObjectID (DigestType SHA512) = [2,16,840,1,101,3,4,2,3]

instance OIDNameable DigestType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

instance AlgorithmId DigestType where
    type AlgorithmType DigestType = DigestType
    algorithmName _  = "digest algorithm"
    algorithmType    = id

    -- MD5 has NULL parameter, other algorithms have no parameter
    parameterASN1S (DigestType MD5) = gNull
    parameterASN1S _                = id

    parseParameter p = getNextMaybe nullOrNothing >> return p

digest :: ByteArrayAccess message => DigestType -> message -> ByteString
digest (DigestType hashAlg) message = B.convert (doHash hashAlg message)

doHash :: (Hash.HashAlgorithm hashAlg, ByteArrayAccess ba)
       => proxy hashAlg -> ba -> Hash.Digest hashAlg
doHash _ = Hash.hash

hashFromProxy :: proxy a -> a
hashFromProxy _ = undefined


-- Cipher-like things

-- | Algorithms that are based on a secret key.  This includes ciphers but also
-- MAC algorithms.
class HasKeySize params where
    -- | Get a specification of the key sizes allowed by the algorithm.
    getKeySizeSpecifier :: params -> KeySizeSpecifier

-- | Return the maximum key size for the specified algorithm.
getMaximumKeySize :: HasKeySize params => params -> Int
getMaximumKeySize params =
    case getKeySizeSpecifier params of
        KeySizeRange _ n -> n
        KeySizeEnum  l   -> maximum l
        KeySizeFixed n   -> n

-- | Return 'True' if the specified key size is valid for the specified
-- algorithm.
validateKeySize :: HasKeySize params => params -> Int -> Bool
validateKeySize params len =
    case getKeySizeSpecifier params of
        KeySizeRange a b -> a <= len && len <= b
        KeySizeEnum  l   -> len `elem` l
        KeySizeFixed n   -> len == n

-- | Generate a random key suitable for the specified algorithm.  This uses the
-- maximum size allowed by the parameters.
generateKey :: (HasKeySize params, MonadRandom m, ByteArray key)
            => params -> m key
generateKey params = getRandomBytes (getMaximumKeySize params)


-- MAC

-- | Message authentication code.  Equality is time constant.
type MessageAuthenticationCode = AuthTag

-- | Message Authentication Code (MAC) Algorithm.
data MACAlgorithm
    = forall hashAlg . Hash.HashAlgorithm hashAlg
        => HMAC (DigestAlgorithm hashAlg)

deriving instance Show MACAlgorithm

instance Eq MACAlgorithm where
    HMAC a1 == HMAC a2 = DigestType a1 == DigestType a2

instance Enumerable MACAlgorithm where
    values = [ HMAC MD5
             , HMAC SHA1
             , HMAC SHA224
             , HMAC SHA256
             , HMAC SHA384
             , HMAC SHA512
             ]

instance OIDable MACAlgorithm where
    getObjectID (HMAC MD5)    = [1,3,6,1,5,5,8,1,1]
    getObjectID (HMAC SHA1)   = [1,3,6,1,5,5,8,1,2]
    getObjectID (HMAC SHA224) = [1,2,840,113549,2,8]
    getObjectID (HMAC SHA256) = [1,2,840,113549,2,9]
    getObjectID (HMAC SHA384) = [1,2,840,113549,2,10]
    getObjectID (HMAC SHA512) = [1,2,840,113549,2,11]

    getObjectID ty = error ("Unsupported MACAlgorithm: " ++ show ty)

instance OIDNameable MACAlgorithm where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

instance AlgorithmId MACAlgorithm where
    type AlgorithmType MACAlgorithm = MACAlgorithm
    algorithmName _  = "mac algorithm"
    algorithmType    = id
    parameterASN1S _ = id
    parseParameter p = getNextMaybe nullOrNothing >> return p

instance HasKeySize MACAlgorithm where
    getKeySizeSpecifier (HMAC a) = KeySizeFixed (digestSizeFromProxy a)
      where digestSizeFromProxy = Hash.hashDigestSize . hashFromProxy

-- | Invoke the MAC function.
mac :: (ByteArrayAccess key, ByteArrayAccess message)
     => MACAlgorithm -> key -> message -> MessageAuthenticationCode
mac (HMAC alg) = hmacWith alg
  where
    hmacWith p key = AuthTag . B.convert . runHMAC p key

    runHMAC :: (Hash.HashAlgorithm a, ByteArrayAccess k, ByteArrayAccess m)
        => proxy a -> k -> m -> HMAC.HMAC a
    runHMAC _ = HMAC.hmac


-- Content encryption

-- | CMS content encryption cipher.
data ContentEncryptionCipher cipher where
    -- | DES
    DES         :: ContentEncryptionCipher Cipher.DES
    -- | Triple-DES with 2 keys used in alternative direction
    DES_EDE2    :: ContentEncryptionCipher Cipher.DES_EDE2
    -- | Triple-DES with 3 keys used in alternative direction
    DES_EDE3    :: ContentEncryptionCipher Cipher.DES_EDE3
    -- | AES with 128-bit key
    AES128      :: ContentEncryptionCipher Cipher.AES128
    -- | AES with 192-bit key
    AES192      :: ContentEncryptionCipher Cipher.AES192
    -- | AES with 256-bit key
    AES256      :: ContentEncryptionCipher Cipher.AES256
    -- | CAST5 (aka CAST-128) with key between 40 and 128 bits
    CAST5       :: ContentEncryptionCipher Cipher.CAST5
    -- | Camellia with 128-bit key
    Camellia128 :: ContentEncryptionCipher Cipher.Camellia128

deriving instance Show (ContentEncryptionCipher cipher)
deriving instance Eq (ContentEncryptionCipher cipher)

cecI :: ContentEncryptionCipher c -> Int
cecI DES         = 0
cecI DES_EDE2    = 1
cecI DES_EDE3    = 2
cecI AES128      = 3
cecI AES192      = 4
cecI AES256      = 5
cecI CAST5       = 6
cecI Camellia128 = 7

getCipherKeySizeSpecifier :: Cipher cipher => proxy cipher -> KeySizeSpecifier
getCipherKeySizeSpecifier = cipherKeySize . cipherFromProxy

-- | Cipher and mode of operation for content encryption.
data ContentEncryptionAlg
    = forall c . BlockCipher c => ECB (ContentEncryptionCipher c)
      -- ^ Electronic Codebook
    | forall c . BlockCipher c => CBC (ContentEncryptionCipher c)
      -- ^ Cipher Block Chaining
    | forall c . BlockCipher c => CFB (ContentEncryptionCipher c)
      -- ^ Cipher Feedback
    | forall c . BlockCipher c => CTR (ContentEncryptionCipher c)
      -- ^ Counter

instance Show ContentEncryptionAlg where
    show (ECB c) = shows c "_ECB"
    show (CBC c) = shows c "_CBC"
    show (CFB c) = shows c "_CFB"
    show (CTR c) = shows c "_CTR"

instance Enumerable ContentEncryptionAlg where
    values = [ CBC DES
             , CBC DES_EDE3
             , CBC AES128
             , CBC AES192
             , CBC AES256
             , CBC CAST5
             , CBC Camellia128

             , ECB DES
             , ECB AES128
             , ECB AES192
             , ECB AES256
             , ECB Camellia128

             , CFB DES
             , CFB AES128
             , CFB AES192
             , CFB AES256
             , CFB Camellia128

             , CTR Camellia128
             ]

instance OIDable ContentEncryptionAlg where
    getObjectID (CBC DES)          = [1,3,14,3,2,7]
    getObjectID (CBC DES_EDE3)     = [1,2,840,113549,3,7]
    getObjectID (CBC AES128)       = [2,16,840,1,101,3,4,1,2]
    getObjectID (CBC AES192)       = [2,16,840,1,101,3,4,1,22]
    getObjectID (CBC AES256)       = [2,16,840,1,101,3,4,1,42]
    getObjectID (CBC CAST5)        = [1,2,840,113533,7,66,10]
    getObjectID (CBC Camellia128)  = [1,2,392,200011,61,1,1,1,2]

    getObjectID (ECB DES)          = [1,3,14,3,2,6]
    getObjectID (ECB AES128)       = [2,16,840,1,101,3,4,1,1]
    getObjectID (ECB AES192)       = [2,16,840,1,101,3,4,1,21]
    getObjectID (ECB AES256)       = [2,16,840,1,101,3,4,1,41]
    getObjectID (ECB Camellia128)  = [0,3,4401,5,3,1,9,1]

    getObjectID (CFB DES)          = [1,3,14,3,2,9]
    getObjectID (CFB AES128)       = [2,16,840,1,101,3,4,1,4]
    getObjectID (CFB AES192)       = [2,16,840,1,101,3,4,1,24]
    getObjectID (CFB AES256)       = [2,16,840,1,101,3,4,1,44]
    getObjectID (CFB Camellia128)  = [0,3,4401,5,3,1,9,4]

    getObjectID (CTR Camellia128)  = [0,3,4401,5,3,1,9,9]

    getObjectID ty = error ("Unsupported ContentEncryptionAlg: " ++ show ty)

instance OIDNameable ContentEncryptionAlg where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

-- | Content encryption algorithm with associated parameters (i.e. the
-- initialization vector).
--
-- A value can be generated with 'generateEncryptionParams'.
data ContentEncryptionParams
    = forall c . BlockCipher c => ParamsECB (ContentEncryptionCipher c)
      -- ^ Electronic Codebook
    | forall c . BlockCipher c => ParamsCBC (ContentEncryptionCipher c) (IV c)
      -- ^ Cipher Block Chaining
    | forall c . BlockCipher c => ParamsCFB (ContentEncryptionCipher c) (IV c)
      -- ^ Cipher Feedback
    | forall c . BlockCipher c => ParamsCTR (ContentEncryptionCipher c) (IV c)
      -- ^ Counter

instance Show ContentEncryptionParams where
    show = show . getContentEncryptionAlg

instance Eq ContentEncryptionParams where
    ParamsECB c1     == ParamsECB c2     = cecI c1 == cecI c2
    ParamsCBC c1 iv1 == ParamsCBC c2 iv2 = cecI c1 == cecI c2 && iv1 `eqBA` iv2
    ParamsCFB c1 iv1 == ParamsCFB c2 iv2 = cecI c1 == cecI c2 && iv1 `eqBA` iv2
    ParamsCTR c1 iv1 == ParamsCTR c2 iv2 = cecI c1 == cecI c2 && iv1 `eqBA` iv2
    _               == _               = False

instance HasKeySize ContentEncryptionParams where
    getKeySizeSpecifier (ParamsECB c)   = getCipherKeySizeSpecifier c
    getKeySizeSpecifier (ParamsCBC c _) = getCipherKeySizeSpecifier c
    getKeySizeSpecifier (ParamsCFB c _) = getCipherKeySizeSpecifier c
    getKeySizeSpecifier (ParamsCTR c _) = getCipherKeySizeSpecifier c

instance ASN1Elem e => ProduceASN1Object e ContentEncryptionParams where
    asn1s param =
        asn1Container Sequence (oid . params)
      where
        oid    = gOID (getObjectID $ getContentEncryptionAlg param)
        params = ceParameterASN1S param

instance Monoid e => ParseASN1Object e ContentEncryptionParams where
    parse = onNextContainer Sequence $ do
        OID oid <- getNext
        withObjectID "content encryption algorithm" oid parseCEParameter

ceParameterASN1S :: ASN1Elem e => ContentEncryptionParams -> ASN1Stream e
ceParameterASN1S (ParamsECB _)    = id
ceParameterASN1S (ParamsCBC _ iv) = gOctetString (B.convert iv)
ceParameterASN1S (ParamsCFB _ iv) = gOctetString (B.convert iv)
ceParameterASN1S (ParamsCTR _ iv) = gOctetString (B.convert iv)

parseCEParameter :: Monoid e
                 => ContentEncryptionAlg -> ParseASN1 e ContentEncryptionParams
parseCEParameter (ECB c) = getMany getNext >> return (ParamsECB c)
parseCEParameter (CBC c) = ParamsCBC c <$> (getNext >>= getIV)
parseCEParameter (CFB c) = ParamsCFB c <$> (getNext >>= getIV)
parseCEParameter (CTR c) = ParamsCTR c <$> (getNext >>= getIV)

getIV :: BlockCipher cipher => ASN1 -> ParseASN1 e (IV cipher)
getIV (OctetString ivBs) =
    case makeIV ivBs of
        Nothing -> throwParseError "Bad IV in parsed parameters"
        Just v  -> return v
getIV _ = throwParseError "No IV in parsed parameter or incorrect format"

-- | Get the content encryption algorithm.
getContentEncryptionAlg :: ContentEncryptionParams -> ContentEncryptionAlg
getContentEncryptionAlg (ParamsECB c)   = ECB c
getContentEncryptionAlg (ParamsCBC c _) = CBC c
getContentEncryptionAlg (ParamsCFB c _) = CFB c
getContentEncryptionAlg (ParamsCTR c _) = CTR c

-- | Generate random parameters for the specified content encryption algorithm.
generateEncryptionParams :: MonadRandom m
                         => ContentEncryptionAlg -> m ContentEncryptionParams
generateEncryptionParams (ECB c) = return (ParamsECB c)
generateEncryptionParams (CBC c) = ParamsCBC c <$> ivGenerate undefined
generateEncryptionParams (CFB c) = ParamsCFB c <$> ivGenerate undefined
generateEncryptionParams (CTR c) = ParamsCTR c <$> ivGenerate undefined

-- | Encrypt a bytearray with the specified content encryption key and
-- algorithm.
contentEncrypt :: (ByteArray cek, ByteArray ba)
               => cek
               -> ContentEncryptionParams
               -> ba -> Either String ba
contentEncrypt key params bs =
    case params of
        ParamsECB cipher    -> getCipher cipher key >>= (\c -> force $ ecbEncrypt c    $ padded c bs)
        ParamsCBC cipher iv -> getCipher cipher key >>= (\c -> force $ cbcEncrypt c iv $ padded c bs)
        ParamsCFB cipher iv -> getCipher cipher key >>= (\c -> force $ cfbEncrypt c iv $ padded c bs)
        ParamsCTR cipher iv -> getCipher cipher key >>= (\c -> force $ ctrCombine c iv $ padded c bs)
  where
    force x  = x `seq` Right x
    padded c = pad (PKCS7 $ blockSize c)

-- | Decrypt a bytearray with the specified content encryption key and
-- algorithm.
contentDecrypt :: (ByteArray cek, ByteArray ba)
               => cek
               -> ContentEncryptionParams
               -> ba -> Either String ba
contentDecrypt key params bs =
    case params of
        ParamsECB cipher    -> getCipher cipher key >>= (\c -> unpadded c (ecbDecrypt c    bs))
        ParamsCBC cipher iv -> getCipher cipher key >>= (\c -> unpadded c (cbcDecrypt c iv bs))
        ParamsCFB cipher iv -> getCipher cipher key >>= (\c -> unpadded c (cfbDecrypt c iv bs))
        ParamsCTR cipher iv -> getCipher cipher key >>= (\c -> unpadded c (ctrCombine c iv bs))
  where
    unpadded c decrypted =
        case unpad (PKCS7 $ blockSize c) decrypted of
            Nothing  -> Left "Decryption failed, incorrect key or password?"
            Just out -> Right out


-- Authenticated-content encryption

-- | Cipher and mode of operation for authenticated-content encryption.
data AuthContentEncryptionAlg
    = AUTH_ENC_128
      -- ^ authEnc with 128-bit key
    | AUTH_ENC_256
      -- ^ authEnc with 256-bit key
    | CHACHA20_POLY1305
      -- ^ ChaCha20-Poly1305 Authenticated Encryption
    | forall c . BlockCipher c => CCM (ContentEncryptionCipher c)
      -- ^ Counter with CBC-MAC
    | forall c . BlockCipher c => GCM (ContentEncryptionCipher c)
      -- ^ Galois Counter Mode

instance Show AuthContentEncryptionAlg where
    show AUTH_ENC_128 = "AUTH_ENC_128"
    show AUTH_ENC_256 = "AUTH_ENC_256"
    show CHACHA20_POLY1305 = "CHACHA20_POLY1305"
    show (CCM c)      = shows c "_CCM"
    show (GCM c)      = shows c "_GCM"

instance Enumerable AuthContentEncryptionAlg where
    values = [ AUTH_ENC_128
             , AUTH_ENC_256
             , CHACHA20_POLY1305

             , CCM AES128
             , CCM AES192
             , CCM AES256

             , GCM AES128
             , GCM AES192
             , GCM AES256
             ]

instance OIDable AuthContentEncryptionAlg where
    getObjectID AUTH_ENC_128       = [1,2,840,113549,1,9,16,3,15]
    getObjectID AUTH_ENC_256       = [1,2,840,113549,1,9,16,3,16]
    getObjectID CHACHA20_POLY1305  = [1,2,840,113549,1,9,16,3,18]

    getObjectID (CCM AES128)       = [2,16,840,1,101,3,4,1,7]
    getObjectID (CCM AES192)       = [2,16,840,1,101,3,4,1,27]
    getObjectID (CCM AES256)       = [2,16,840,1,101,3,4,1,47]

    getObjectID (GCM AES128)       = [2,16,840,1,101,3,4,1,6]
    getObjectID (GCM AES192)       = [2,16,840,1,101,3,4,1,26]
    getObjectID (GCM AES256)       = [2,16,840,1,101,3,4,1,46]

    getObjectID ty = error ("Unsupported AuthContentEncryptionAlg: " ++ show ty)

instance OIDNameable AuthContentEncryptionAlg where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

data AuthEncParams = AuthEncParams
    { prfAlgorithm :: PBKDF2_PRF
    , encAlgorithm :: ContentEncryptionParams
    , macAlgorithm :: MACAlgorithm
    }
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e AuthEncParams where
    asn1s AuthEncParams{..} = asn1Container Sequence (kdf . encAlg . macAlg)
      where
        kdf    = algorithmASN1S (Container Context 0) (asKDF prfAlgorithm)
        encAlg = asn1s encAlgorithm
        macAlg = algorithmASN1S Sequence macAlgorithm

        asKDF algPrf = PBKDF2 { pbkdf2Salt = B.empty
                              , pbkdf2IterationCount = 1
                              , pbkdf2KeyLength = Nothing
                              , pbkdf2Prf = algPrf
                              }

instance Monoid e => ParseASN1Object e AuthEncParams where
    parse = onNextContainer Sequence $ do
        kdf    <- parseAlgorithmMaybe (Container Context 0)
        encAlg <- parse
        macAlg <- parseAlgorithm Sequence
        prfAlg <-
            case kdf of
                Nothing               -> return PBKDF2_SHA1
                Just (PBKDF2 _ _ _ a) -> return a
                Just other            -> throwParseError
                    ("Unable to use " ++ show other ++ " in AuthEncParams")
        return AuthEncParams { prfAlgorithm = prfAlg
                             , encAlgorithm = encAlg
                             , macAlgorithm = macAlg
                             }

-- | Authenticated-content encryption algorithm with associated parameters
-- (i.e. the nonce).
--
-- A value can be generated with functions 'generateAuthEnc128Params',
-- 'generateAuthEnc256Params', 'generateChaChaPoly1305Params',
-- 'generateCCMParams' and 'generateGCMParams'.
data AuthContentEncryptionParams
    = Params_AUTH_ENC_128 AuthEncParams
      -- ^ authEnc with 128-bit keying material
    | Params_AUTH_ENC_256 AuthEncParams
      -- ^ authEnc with 256-bit keying material
    | Params_CHACHA20_POLY1305 ChaChaPoly1305.Nonce
      -- ^ ChaCha20-Poly1305 Authenticated Encryption
    | forall c . BlockCipher c => ParamsCCM (ContentEncryptionCipher c) B.Bytes CCM_M CCM_L
      -- ^ Counter with CBC-MAC
    | forall c . BlockCipher c => ParamsGCM (ContentEncryptionCipher c) B.Bytes Int
      -- ^ Galois Counter Mode

instance Show AuthContentEncryptionParams where
    show = show . getAuthContentEncryptionAlg

instance Eq AuthContentEncryptionParams where
    Params_AUTH_ENC_128 p1 == Params_AUTH_ENC_128 p2 = p1 == p2
    Params_AUTH_ENC_256 p1 == Params_AUTH_ENC_256 p2 = p1 == p2
    Params_CHACHA20_POLY1305 iv1 == Params_CHACHA20_POLY1305 iv2 =
        iv1 `eqBA` iv2

    ParamsCCM c1 iv1 m1 l1 == ParamsCCM c2 iv2 m2 l2 =
        cecI c1 == cecI c2 && iv1 == iv2 && (m1, l1) == (m2, l2)
    ParamsGCM c1 iv1 len1  == ParamsGCM c2 iv2 len2  =
        cecI c1 == cecI c2 && iv1 == iv2 && len1 == len2
    _               == _               = False

instance HasKeySize AuthContentEncryptionParams where
    getKeySizeSpecifier (Params_AUTH_ENC_128 _) = KeySizeFixed 16
    getKeySizeSpecifier (Params_AUTH_ENC_256 _) = KeySizeFixed 32
    getKeySizeSpecifier (Params_CHACHA20_POLY1305 _) = KeySizeFixed 32
    getKeySizeSpecifier (ParamsCCM c _ _ _)     = getCipherKeySizeSpecifier c
    getKeySizeSpecifier (ParamsGCM c _ _)       = getCipherKeySizeSpecifier c

instance ASN1Elem e => ProduceASN1Object e AuthContentEncryptionParams where
    asn1s param =
        asn1Container Sequence (oid . params)
      where
        oid    = gOID (getObjectID $ getAuthContentEncryptionAlg param)
        params = aceParameterASN1S param

instance Monoid e => ParseASN1Object e AuthContentEncryptionParams where
    parse = onNextContainer Sequence $ do
        OID oid <- getNext
        withObjectID "authenticated-content encryption algorithm" oid
            parseACEParameter

aceParameterASN1S :: ASN1Elem e => AuthContentEncryptionParams -> ASN1Stream e
aceParameterASN1S (Params_AUTH_ENC_128 p) = asn1s p
aceParameterASN1S (Params_AUTH_ENC_256 p) = asn1s p
aceParameterASN1S (Params_CHACHA20_POLY1305 iv) = gOctetString (B.convert iv)
aceParameterASN1S (ParamsCCM _ iv m _) =
    asn1Container Sequence (nonce . icvlen)
  where
    nonce  = gOctetString (B.convert iv)
    icvlen = gIntVal (fromIntegral $ getM m)
aceParameterASN1S (ParamsGCM _ iv len) =
    asn1Container Sequence (nonce . icvlen)
  where
    nonce  = gOctetString (B.convert iv)
    icvlen = gIntVal (fromIntegral len)

parseACEParameter :: Monoid e
                  => AuthContentEncryptionAlg
                  -> ParseASN1 e AuthContentEncryptionParams
parseACEParameter AUTH_ENC_128 = Params_AUTH_ENC_128 <$> parse
parseACEParameter AUTH_ENC_256 = Params_AUTH_ENC_256 <$> parse
parseACEParameter CHACHA20_POLY1305 = do
    OctetString bs <- getNext
    case ChaChaPoly1305.nonce12 bs of
        CryptoPassed iv -> return (Params_CHACHA20_POLY1305 iv)
        CryptoFailed e  ->
            throwParseError $ "Parsed invalid ChaChaPoly1305 nonce: " ++ show e
parseACEParameter (CCM c)      = onNextContainer Sequence $ do
    OctetString iv <- getNext
    let ivlen = B.length iv
    when (ivlen < 7 || ivlen > 13) $
        throwParseError $ "Parsed invalid CCM nonce length: " ++ show ivlen
    let Just l = fromL (15 - ivlen)
    m <- parseM
    return (ParamsCCM c (B.convert iv) m l)
parseACEParameter (GCM c)      = onNextContainer Sequence $ do
    OctetString iv <- getNext
    when (B.null iv) $
        throwParseError "Parsed empty GCM nonce"
    icvlen <- fromMaybe 12 <$> getNextMaybe intOrNothing
    when (icvlen < 12 || icvlen > 16) $
        throwParseError $ "Parsed invalid GCM ICV length: " ++ show icvlen
    return (ParamsGCM c (B.convert iv) $ fromIntegral icvlen)

-- | Get the authenticated-content encryption algorithm.
getAuthContentEncryptionAlg :: AuthContentEncryptionParams
                            -> AuthContentEncryptionAlg
getAuthContentEncryptionAlg (Params_AUTH_ENC_128 _) = AUTH_ENC_128
getAuthContentEncryptionAlg (Params_AUTH_ENC_256 _) = AUTH_ENC_256
getAuthContentEncryptionAlg (Params_CHACHA20_POLY1305 _) = CHACHA20_POLY1305
getAuthContentEncryptionAlg (ParamsCCM c _ _ _)     = CCM c
getAuthContentEncryptionAlg (ParamsGCM c _ _)       = GCM c

-- | Generate random 'AUTH_ENC_128' parameters with the specified algorithms.
generateAuthEnc128Params :: MonadRandom m
                         => PBKDF2_PRF -> ContentEncryptionAlg -> MACAlgorithm
                         -> m AuthContentEncryptionParams
generateAuthEnc128Params prfAlg cea macAlg = do
    params <- generateEncryptionParams cea
    return $ Params_AUTH_ENC_128 $
        AuthEncParams { prfAlgorithm = prfAlg
                      , encAlgorithm = params
                      , macAlgorithm = macAlg
                      }

-- | Generate random 'AUTH_ENC_256' parameters with the specified algorithms.
generateAuthEnc256Params :: MonadRandom m
                         => PBKDF2_PRF -> ContentEncryptionAlg -> MACAlgorithm
                         -> m AuthContentEncryptionParams
generateAuthEnc256Params prfAlg cea macAlg = do
    params <- generateEncryptionParams cea
    return $ Params_AUTH_ENC_256 $
        AuthEncParams { prfAlgorithm = prfAlg
                      , encAlgorithm = params
                      , macAlgorithm = macAlg
                      }

-- | Generate random 'CHACHA20_POLY1305' parameters.
generateChaChaPoly1305Params :: MonadRandom m => m AuthContentEncryptionParams
generateChaChaPoly1305Params = do
    bs <- nonceGenerate 12
    let iv = throwCryptoError (ChaChaPoly1305.nonce12 bs)
    return (Params_CHACHA20_POLY1305 iv)

-- | Generate random 'CCM' parameters for the specified cipher.
generateCCMParams :: (MonadRandom m, BlockCipher c)
                  => ContentEncryptionCipher c -> CCM_M -> CCM_L
                  -> m AuthContentEncryptionParams
generateCCMParams c m l = do
    iv <- nonceGenerate (15 - getL l)
    return (ParamsCCM c iv m l)

-- | Generate random 'GCM' parameters for the specified cipher.
generateGCMParams :: (MonadRandom m, BlockCipher c)
                  => ContentEncryptionCipher c -> Int
                  -> m AuthContentEncryptionParams
generateGCMParams c l = do
    iv <- nonceGenerate 12
    return (ParamsGCM c iv l)

-- | Encrypt a bytearray with the specified authenticated-content encryption
-- key and algorithm.
authContentEncrypt :: forall cek aad ba . (ByteArray cek, ByteArrayAccess aad, ByteArray ba)
                   => cek
                   -> AuthContentEncryptionParams -> ba
                   -> aad -> ba -> Either String (AuthTag, ba)
authContentEncrypt key params paramsRaw aad bs =
    case params of
        Params_AUTH_ENC_128 p   -> checkAuthKey 16 key >> authEncrypt p
        Params_AUTH_ENC_256 p   -> checkAuthKey 32 key >> authEncrypt p
        Params_CHACHA20_POLY1305 iv -> ccpInit key iv aad >>= ccpEncrypt
        ParamsCCM cipher iv m l -> getAEAD cipher key (AEAD_CCM msglen m l) iv >>= encrypt (getM m)
        ParamsGCM cipher iv len -> getAEAD cipher key AEAD_GCM iv >>= encrypt len
  where
    msglen  = B.length bs
    force x = x `seq` Right x

    encrypt :: Int -> AEAD a -> Either String (AuthTag, ba)
    encrypt len aead = force $ aeadSimpleEncrypt aead aad bs len

    ccpEncrypt :: ChaChaPoly1305.State -> Either a (AuthTag, ba)
    ccpEncrypt state = force (found, encrypted)
      where
        (encrypted, state') = ChaChaPoly1305.encrypt bs state
        found = ccpTag (ChaChaPoly1305.finalize state')

    authEncrypt :: AuthEncParams -> Either String (AuthTag, ba)
    authEncrypt p@AuthEncParams{..} = do
        let (encKey, macKey) = authKeys key p
        encrypted <- contentEncrypt encKey encAlgorithm bs
        let macMsg = paramsRaw `B.append` encrypted `B.append` B.convert aad
            found  = mac macAlgorithm macKey macMsg
        return (found, encrypted)

-- | Decrypt a bytearray with the specified authenticated-content encryption key
-- and algorithm.
authContentDecrypt :: forall cek aad ba . (ByteArray cek, ByteArrayAccess aad, ByteArray ba)
                   => cek
                   -> AuthContentEncryptionParams -> ba
                   -> aad -> ba -> AuthTag -> Either String ba
authContentDecrypt key params paramsRaw aad bs expected =
    case params of
        Params_AUTH_ENC_128 p   -> checkAuthKey 16 key >> authDecrypt p
        Params_AUTH_ENC_256 p   -> checkAuthKey 32 key >> authDecrypt p
        Params_CHACHA20_POLY1305 iv -> ccpInit key iv aad >>= ccpDecrypt
        ParamsCCM cipher iv m l -> getAEAD cipher key (AEAD_CCM msglen m l) iv >>= decrypt
        ParamsGCM cipher iv _   -> getAEAD cipher key AEAD_GCM iv >>= decrypt
  where
    msglen  = B.length bs
    badMac  = Left "Bad content MAC"

    decrypt :: AEAD a -> Either String ba
    decrypt aead = maybe badMac Right (aeadSimpleDecrypt aead aad bs expected)

    ccpDecrypt :: ChaChaPoly1305.State -> Either String ba
    ccpDecrypt state
        | found == expected = Right decrypted
        | otherwise         = badMac
      where
        (decrypted, state') = ChaChaPoly1305.decrypt bs state
        found = ccpTag (ChaChaPoly1305.finalize state')

    authDecrypt :: AuthEncParams -> Either String ba
    authDecrypt p@AuthEncParams{..}
        | found == expected = contentDecrypt encKey encAlgorithm bs
        | otherwise         = badMac
      where
        (encKey, macKey) = authKeys key p
        macMsg = paramsRaw `B.append` bs `B.append` B.convert aad
        found  = mac macAlgorithm macKey macMsg

getAEAD :: (BlockCipher cipher, ByteArray key, ByteArrayAccess iv)
        => proxy cipher -> key -> AEADMode -> iv -> Either String (AEAD cipher)
getAEAD cipher key mode iv = do
    c <- getCipher cipher key
    onCryptoFailure (Left . show) Right $ aeadInit mode c iv

authKeys :: ByteArrayAccess password
         => password -> AuthEncParams
         -> (B.ScrubbedBytes, B.ScrubbedBytes)
authKeys key AuthEncParams{..} = (encKey, macKey)
  where
    encKDF = PBKDF2 "encryption" 1 Nothing prfAlgorithm
    encLen = getMaximumKeySize encAlgorithm
    encKey = kdfDerive encKDF encLen key

    macKDF = PBKDF2 "authentication" 1 Nothing prfAlgorithm
    macKey = kdfDerive macKDF macLen key

    -- RFC 6476 section 4.2: "Specifying a MAC key size gets a bit tricky"
    -- TODO: this is a hack but allows both test vectors to pass
    macLen | encLen == 24 = 16
           | otherwise    = getMaximumKeySize macAlgorithm

checkAuthKey :: ByteArrayAccess cek => Int -> cek -> Either String ()
checkAuthKey sz key
    | actual == sz = Right ()
    | otherwise    =
        Left ("Expecting " ++ show sz ++ "-byte key instead of " ++ show actual)
  where actual = B.length key

ccpInit :: (ByteArrayAccess key, ByteArrayAccess aad)
        => key
        -> ChaChaPoly1305.Nonce
        -> aad
        -> Either String ChaChaPoly1305.State
ccpInit key nonce aad = case ChaChaPoly1305.initialize key nonce of
    CryptoPassed s -> return (addAAD s)
    CryptoFailed e -> Left ("Invalid ChaChaPoly1305 parameters: " ++ show e)
  where addAAD = ChaChaPoly1305.finalizeAAD . ChaChaPoly1305.appendAAD aad

ccpTag :: Poly1305.Auth -> AuthTag
ccpTag (Poly1305.Auth bs) = AuthTag bs

-- PRF

-- | Pseudorandom function used for PBKDF2.
data PBKDF2_PRF = PBKDF2_SHA1   -- ^ hmacWithSHA1
                | PBKDF2_SHA256 -- ^ hmacWithSHA256
                | PBKDF2_SHA512 -- ^ hmacWithSHA512
                deriving (Show,Eq)

instance Enumerable PBKDF2_PRF where
    values = [ PBKDF2_SHA1
             , PBKDF2_SHA256
             , PBKDF2_SHA512
             ]

instance OIDable PBKDF2_PRF where
    getObjectID PBKDF2_SHA1   = [1,2,840,113549,2,7]
    getObjectID PBKDF2_SHA256 = [1,2,840,113549,2,9]
    getObjectID PBKDF2_SHA512 = [1,2,840,113549,2,11]

instance OIDNameable PBKDF2_PRF where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

instance AlgorithmId PBKDF2_PRF where
    type AlgorithmType PBKDF2_PRF = PBKDF2_PRF
    algorithmName _  = "PBKDF2 PRF"
    algorithmType    = id
    parameterASN1S _ = id
    parseParameter p = getNextMaybe nullOrNothing >> return p

-- | Invoke the pseudorandom function.
prf :: (ByteArrayAccess salt, ByteArrayAccess password, ByteArray out)
    => PBKDF2_PRF -> PBKDF2.Parameters -> password -> salt -> out
prf PBKDF2_SHA1   = PBKDF2.fastPBKDF2_SHA1
prf PBKDF2_SHA256 = PBKDF2.fastPBKDF2_SHA256
prf PBKDF2_SHA512 = PBKDF2.fastPBKDF2_SHA512


-- Key derivation

-- | Salt value used for key derivation.
type Salt = ByteString

-- | Key derivation algorithm.
data KeyDerivationAlgorithm = TypePBKDF2 | TypeScrypt

instance Enumerable KeyDerivationAlgorithm where
    values = [ TypePBKDF2
             , TypeScrypt
             ]

instance OIDable KeyDerivationAlgorithm where
    getObjectID TypePBKDF2 = [1,2,840,113549,1,5,12]
    getObjectID TypeScrypt = [1,3,6,1,4,1,11591,4,11]

instance OIDNameable KeyDerivationAlgorithm where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

-- | Key derivation algorithm and associated parameters.
data KeyDerivationFunc =
      -- | Key derivation with PBKDF2
      PBKDF2 { pbkdf2Salt           :: Salt       -- ^ Salt value
             , pbkdf2IterationCount :: Int        -- ^ Iteration count
             , pbkdf2KeyLength      :: Maybe Int  -- ^ Optional key length
             , pbkdf2Prf            :: PBKDF2_PRF -- ^ Pseudorandom function
             }
      -- | Key derivation with Scrypt
    | Scrypt { scryptSalt      :: Salt       -- ^ Salt value
             , scryptN         :: Word64     -- ^ N value
             , scryptR         :: Int        -- ^ R value
             , scryptP         :: Int        -- ^ P value
             , scryptKeyLength :: Maybe Int  -- ^ Optional key length
             }
    deriving (Show,Eq)

instance AlgorithmId KeyDerivationFunc where
    type AlgorithmType KeyDerivationFunc = KeyDerivationAlgorithm

    algorithmName _ = "key derivation algorithm"
    algorithmType PBKDF2{..} = TypePBKDF2
    algorithmType Scrypt{..} = TypeScrypt

    parameterASN1S PBKDF2{..} =
        asn1Container Sequence (salt . iters . keyLen . mprf)
      where
        salt   = gOctetString pbkdf2Salt
        iters  = gIntVal (toInteger pbkdf2IterationCount)
        keyLen = maybe id (gIntVal . toInteger) pbkdf2KeyLength
        mprf   = if pbkdf2Prf == PBKDF2_SHA1 then id else algorithmASN1S Sequence pbkdf2Prf

    parameterASN1S Scrypt{..} =
        asn1Container Sequence (salt . n . r . p . keyLen)
      where
        salt   = gOctetString scryptSalt
        n      = gIntVal (toInteger scryptN)
        r      = gIntVal (toInteger scryptR)
        p      = gIntVal (toInteger scryptP)
        keyLen = maybe id (gIntVal . toInteger) scryptKeyLength

    parseParameter TypePBKDF2 = onNextContainer Sequence $ do
        OctetString salt <- getNext
        IntVal iters <- getNext
        keyLen <- getNextMaybe intOrNothing
        b <- hasNext
        mprf <- if b then parseAlgorithm Sequence else return PBKDF2_SHA1
        return PBKDF2 { pbkdf2Salt           = salt
                      , pbkdf2IterationCount = fromInteger iters
                      , pbkdf2KeyLength      = fromInteger <$> keyLen
                      , pbkdf2Prf            = mprf
                      }

    parseParameter TypeScrypt = onNextContainer Sequence $ do
        OctetString salt <- getNext
        IntVal n <- getNext
        IntVal r <- getNext
        IntVal p <- getNext
        keyLen <- getNextMaybe intOrNothing
        return Scrypt { scryptSalt      = salt
                      , scryptN         = fromInteger n
                      , scryptR         = fromInteger r
                      , scryptP         = fromInteger p
                      , scryptKeyLength = fromInteger <$> keyLen
                      }

-- | Return the optional key length stored in the KDF parameters.
kdfKeyLength :: KeyDerivationFunc -> Maybe Int
kdfKeyLength PBKDF2{..} = pbkdf2KeyLength
kdfKeyLength Scrypt{..} = scryptKeyLength

-- | Run a key derivation function to produce a result of the specified length
-- using the supplied password.
kdfDerive :: (ByteArrayAccess password, ByteArray out)
          => KeyDerivationFunc -> Int -> password -> out
kdfDerive PBKDF2{..} len pwd = prf pbkdf2Prf params pwd pbkdf2Salt
  where params = PBKDF2.Parameters pbkdf2IterationCount len
kdfDerive Scrypt{..} len pwd = Scrypt.generate params pwd scryptSalt
  where params = Scrypt.Parameters { Scrypt.n = scryptN
                                   , Scrypt.r = scryptR
                                   , Scrypt.p = scryptP
                                   , Scrypt.outputLength = len
                                   }

-- | Generate a random salt with the specified length in bytes.  To be most
-- effective, the length should be at least 8 bytes.
generateSalt :: MonadRandom m => Int -> m Salt
generateSalt = getRandomBytes


-- Key encryption

data KeyEncryptionType = TypePWRIKEK
                       | TypeAES128_WRAP
                       | TypeAES192_WRAP
                       | TypeAES256_WRAP
                       | TypeAES128_WRAP_PAD
                       | TypeAES192_WRAP_PAD
                       | TypeAES256_WRAP_PAD
                       | TypeDES_EDE3_WRAP

instance Enumerable KeyEncryptionType where
    values = [ TypePWRIKEK
             , TypeAES128_WRAP
             , TypeAES192_WRAP
             , TypeAES256_WRAP
             , TypeAES128_WRAP_PAD
             , TypeAES192_WRAP_PAD
             , TypeAES256_WRAP_PAD
             , TypeDES_EDE3_WRAP
             ]

instance OIDable KeyEncryptionType where
    getObjectID TypePWRIKEK         = [1,2,840,113549,1,9,16,3,9]

    getObjectID TypeAES128_WRAP     = [2,16,840,1,101,3,4,1,5]
    getObjectID TypeAES192_WRAP     = [2,16,840,1,101,3,4,1,25]
    getObjectID TypeAES256_WRAP     = [2,16,840,1,101,3,4,1,45]

    getObjectID TypeAES128_WRAP_PAD = [2,16,840,1,101,3,4,1,8]
    getObjectID TypeAES192_WRAP_PAD = [2,16,840,1,101,3,4,1,28]
    getObjectID TypeAES256_WRAP_PAD = [2,16,840,1,101,3,4,1,48]

    getObjectID TypeDES_EDE3_WRAP   = [1,2,840,113549,1,9,16,3,6]

instance OIDNameable KeyEncryptionType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

-- | Key encryption algorithm with associated parameters (i.e. the underlying
-- encryption algorithm).
data KeyEncryptionParams = PWRIKEK ContentEncryptionParams  -- ^ PWRI-KEK key wrap algorithm
                         | AES128_WRAP                      -- ^ AES-128 key wrap
                         | AES192_WRAP                      -- ^ AES-192 key wrap
                         | AES256_WRAP                      -- ^ AES-256 key wrap
                         | AES128_WRAP_PAD                  -- ^ AES-128 extended key wrap
                         | AES192_WRAP_PAD                  -- ^ AES-192 extended key wrap
                         | AES256_WRAP_PAD                  -- ^ AES-256 extended key wrap
                         | DES_EDE3_WRAP                    -- ^ Triple-DES key wrap
                         deriving (Show,Eq)

instance AlgorithmId KeyEncryptionParams where
    type AlgorithmType KeyEncryptionParams = KeyEncryptionType
    algorithmName _ = "key encryption algorithm"

    algorithmType (PWRIKEK _)      = TypePWRIKEK
    algorithmType AES128_WRAP      = TypeAES128_WRAP
    algorithmType AES192_WRAP      = TypeAES192_WRAP
    algorithmType AES256_WRAP      = TypeAES256_WRAP
    algorithmType AES128_WRAP_PAD  = TypeAES128_WRAP_PAD
    algorithmType AES192_WRAP_PAD  = TypeAES192_WRAP_PAD
    algorithmType AES256_WRAP_PAD  = TypeAES256_WRAP_PAD
    algorithmType DES_EDE3_WRAP    = TypeDES_EDE3_WRAP

    parameterASN1S (PWRIKEK cep)  = asn1s cep
    parameterASN1S DES_EDE3_WRAP  = gNull
    parameterASN1S _              = id

    parseParameter TypePWRIKEK          = PWRIKEK <$> parse
    parseParameter TypeAES128_WRAP      = return AES128_WRAP
    parseParameter TypeAES192_WRAP      = return AES192_WRAP
    parseParameter TypeAES256_WRAP      = return AES256_WRAP
    parseParameter TypeAES128_WRAP_PAD  = return AES128_WRAP_PAD
    parseParameter TypeAES192_WRAP_PAD  = return AES192_WRAP_PAD
    parseParameter TypeAES256_WRAP_PAD  = return AES256_WRAP_PAD
    parseParameter TypeDES_EDE3_WRAP    = getNextMaybe nullOrNothing >> return DES_EDE3_WRAP

instance HasKeySize KeyEncryptionParams where
    getKeySizeSpecifier (PWRIKEK cep)   = getKeySizeSpecifier cep
    getKeySizeSpecifier AES128_WRAP     = getCipherKeySizeSpecifier AES128
    getKeySizeSpecifier AES192_WRAP     = getCipherKeySizeSpecifier AES192
    getKeySizeSpecifier AES256_WRAP     = getCipherKeySizeSpecifier AES256
    getKeySizeSpecifier AES128_WRAP_PAD = getCipherKeySizeSpecifier AES128
    getKeySizeSpecifier AES192_WRAP_PAD = getCipherKeySizeSpecifier AES192
    getKeySizeSpecifier AES256_WRAP_PAD = getCipherKeySizeSpecifier AES256
    getKeySizeSpecifier DES_EDE3_WRAP   = getCipherKeySizeSpecifier DES_EDE3

-- | Encrypt a key with the specified key encryption key and algorithm.
keyEncrypt :: (MonadRandom m, ByteArray kek, ByteArray ba)
           => kek -> KeyEncryptionParams -> ba -> m (Either String ba)
keyEncrypt key (PWRIKEK params) bs =
    case params of
        ParamsECB cipher    -> let cc = getCipher cipher key in either (return . Left) (\c -> wrapEncrypt (const . ecbEncrypt) c undefined bs) cc
        ParamsCBC cipher iv -> let cc = getCipher cipher key in either (return . Left) (\c -> wrapEncrypt cbcEncrypt c iv bs) cc
        ParamsCFB cipher iv -> let cc = getCipher cipher key in either (return . Left) (\c -> wrapEncrypt cfbEncrypt c iv bs) cc
        ParamsCTR _ _       -> return (Left "Unable to wrap key in CTR mode")
keyEncrypt key AES128_WRAP      bs = return (getCipher AES128 key >>= (`AES_KW.wrap` bs))
keyEncrypt key AES192_WRAP      bs = return (getCipher AES192 key >>= (`AES_KW.wrap` bs))
keyEncrypt key AES256_WRAP      bs = return (getCipher AES256 key >>= (`AES_KW.wrap` bs))
keyEncrypt key AES128_WRAP_PAD  bs = return (getCipher AES128 key >>= (`AES_KW.wrapPad` bs))
keyEncrypt key AES192_WRAP_PAD  bs = return (getCipher AES192 key >>= (`AES_KW.wrapPad` bs))
keyEncrypt key AES256_WRAP_PAD  bs = return (getCipher AES256 key >>= (`AES_KW.wrapPad` bs))
keyEncrypt key DES_EDE3_WRAP    bs = either (return . Left) (wrap3DES bs) (getCipher DES_EDE3 key)
  where wrap3DES b c = (\iv -> TripleDES_KW.wrap c iv b) <$> ivGenerate c

-- | Decrypt a key with the specified key encryption key and algorithm.
keyDecrypt :: (ByteArray kek, ByteArray ba)
           => kek -> KeyEncryptionParams -> ba -> Either String ba
keyDecrypt key (PWRIKEK params) bs =
    case params of
        ParamsECB cipher    -> getCipher cipher key >>= (\c -> wrapDecrypt (const . ecbDecrypt) c undefined bs)
        ParamsCBC cipher iv -> getCipher cipher key >>= (\c -> wrapDecrypt cbcDecrypt c iv bs)
        ParamsCFB cipher iv -> getCipher cipher key >>= (\c -> wrapDecrypt cfbDecrypt c iv bs)
        ParamsCTR _ _       -> Left "Unable to unwrap key in CTR mode"
keyDecrypt key AES128_WRAP      bs = getCipher AES128   key >>= (`AES_KW.unwrap` bs)
keyDecrypt key AES192_WRAP      bs = getCipher AES192   key >>= (`AES_KW.unwrap` bs)
keyDecrypt key AES256_WRAP      bs = getCipher AES256   key >>= (`AES_KW.unwrap` bs)
keyDecrypt key AES128_WRAP_PAD  bs = getCipher AES128   key >>= (`AES_KW.unwrapPad` bs)
keyDecrypt key AES192_WRAP_PAD  bs = getCipher AES192   key >>= (`AES_KW.unwrapPad` bs)
keyDecrypt key AES256_WRAP_PAD  bs = getCipher AES256   key >>= (`AES_KW.unwrapPad` bs)
keyDecrypt key DES_EDE3_WRAP    bs = getCipher DES_EDE3 key >>= (`TripleDES_KW.unwrap` bs)

keyWrap :: (MonadRandom m, ByteArray ba)
        => Int -> ba -> m (Either String ba)
keyWrap sz input
    | inLen <   3 = return $ Left "keyWrap: input key too short"
    | inLen > 255 = return $ Left "keyWrap: input key too long"
    | pLen == 0   = return $ Right $ B.concat [ count, check, input ]
    | otherwise   = do
        padding <- getRandomBytes pLen
        return $ Right $ B.concat [ count, check, input, padding ]
  where
    inLen = B.length input
    count = B.singleton (fromIntegral inLen)
    check = B.xor input (B.pack [255, 255, 255] :: B.Bytes)
    pLen  = sz - (inLen + 4) `mod` sz + comp
    comp  = if inLen + 4 > sz then 0 else sz

keyUnwrap :: ByteArray ba => ba -> Either String ba
keyUnwrap input
    | inLen < 4         = Left "keyUnwrap: invalid wrapped key"
    | check /= 255      = Left "keyUnwrap: invalid wrapped key"
    | inLen < count - 4 = Left "keyUnwrap: invalid wrapped key"
    | otherwise         = Right $ B.take count (B.drop 4 input)
  where
    inLen = B.length input
    count = fromIntegral (B.index input 0)
    bytes = [ B.index input (i + 1) `xor` B.index input (i + 4) | i <- [0..2] ]
    check = foldl1 (.&.) bytes

wrapEncrypt :: (MonadRandom m, BlockCipher cipher, ByteArray ba)
            => (cipher -> IV cipher -> ba -> ba)
            -> cipher -> IV cipher -> ba -> m (Either String ba)
wrapEncrypt encFn cipher iv input = do
    wrapped <- keyWrap sz input
    return (fn <$> wrapped)
  where
    sz = blockSize cipher
    fn formatted =
        let firstPass = encFn cipher iv formatted
            lastBlock = B.drop (B.length firstPass - sz) firstPass
            Just iv'  = makeIV lastBlock
         in encFn cipher iv' firstPass

wrapDecrypt :: (BlockCipher cipher, ByteArray ba)
            => (cipher -> IV cipher -> ba -> ba)
            -> cipher -> IV cipher -> ba -> Either String ba
wrapDecrypt decFn cipher iv input = keyUnwrap (decFn cipher iv firstPass)
  where
    sz = blockSize cipher
    (beg, lb) = B.splitAt (B.length input - sz) input
    lastBlock = decFn cipher iv' lb
    Just iv'  = makeIV (B.drop (B.length beg - sz) beg)
    Just iv'' = makeIV lastBlock
    firstPass = decFn cipher iv'' beg `B.append` lastBlock


-- Utilities

getCipher :: (BlockCipher cipher, ByteArray key)
          => proxy cipher -> key -> Either String cipher
getCipher _ key =
    case cipherInit key of
        CryptoPassed c -> Right c
        CryptoFailed e -> Left ("Unable to use key: " ++ show e)

ivGenerate :: (BlockCipher cipher, MonadRandom m) => cipher -> m (IV cipher)
ivGenerate cipher = do
    bs <- getRandomBytes (blockSize cipher)
    let Just iv = makeIV (bs :: ByteString)
    return iv

nonceGenerate :: MonadRandom m => Int -> m B.Bytes
nonceGenerate = getRandomBytes

cipherFromProxy :: proxy cipher -> cipher
cipherFromProxy _ = undefined

-- | Return the block size of the specified block cipher.
proxyBlockSize :: BlockCipher cipher => proxy cipher -> Int
proxyBlockSize = blockSize . cipherFromProxy

getL :: CCM_L -> Int
getL CCM_L2 = 2
getL CCM_L3 = 3
getL CCM_L4 = 4

getM :: CCM_M -> Int
getM CCM_M4  = 4
getM CCM_M6  = 6
getM CCM_M8  = 8
getM CCM_M10 = 10
getM CCM_M12 = 12
getM CCM_M14 = 14
getM CCM_M16 = 16

fromL :: Int -> Maybe CCM_L
fromL 2 = Just CCM_L2
fromL 3 = Just CCM_L3
fromL 4 = Just CCM_L4
fromL _ = Nothing

parseM :: Monoid e => ParseASN1 e CCM_M
parseM = do
    IntVal l <- getNext
    case l of
        4  -> return CCM_M4
        6  -> return CCM_M6
        8  -> return CCM_M8
        10 -> return CCM_M10
        12 -> return CCM_M12
        14 -> return CCM_M14
        16 -> return CCM_M16
        i -> throwParseError ("Parsed invalid CCM parameter M: " ++ show i)
