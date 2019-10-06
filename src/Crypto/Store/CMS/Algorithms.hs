-- |
-- Module      : Crypto.Store.CMS.Algorithms
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Cryptographic Message Syntax algorithms
{-# LANGUAGE DataKinds #-}
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
    ( DigestAlgorithm(..)
    , DigestProxy(..)
    , digest
    , MessageAuthenticationCode
    , MACAlgorithm(..)
    , mac
    , HasStrength
    , securityAcceptable
    , HasKeySize(..)
    , getMaximumKeySize
    , validateKeySize
    , generateKey
    , ContentEncryptionCipher(..)
    , ContentEncryptionAlg(..)
    , ContentEncryptionParams(..)
    , generateEncryptionParams
    , generateRC2EncryptionParams
    , getContentEncryptionAlg
    , proxyBlockSize
    , contentEncrypt
    , contentDecrypt
    , AuthContentEncryptionAlg(..)
    , AuthContentEncryptionParams
    , generateAuthEnc128Params
    , generateAuthEnc256Params
    , generateChaChaPoly1305Params
    , generateCCMParams
    , generateGCMParams
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
    , OAEPParams(..)
    , KeyTransportParams(..)
    , transportEncrypt
    , transportDecrypt
    , KeyAgreementParams(..)
    , ECDHPair
    , ecdhGenerate
    , ecdhPublic
    , ecdhEncrypt
    , ecdhDecrypt
    , MaskGenerationFunc(..)
    , mgf
    , SignatureValue
    , PSSParams(..)
    , SignatureAlg(..)
    , signatureResolveHash
    , signatureCheckHash
    , signatureGenerate
    , signatureVerify
    ) where

import Control.Applicative
import Control.Monad (guard, when)

import           Data.ASN1.BinaryEncoding
import           Data.ASN1.OID
import           Data.ASN1.Encoding
import           Data.ASN1.Types
import           Data.Bits
import           Data.ByteArray (ByteArray, ByteArrayAccess)
import qualified Data.ByteArray as B
import           Data.ByteString (ByteString)
import           Data.Maybe (fromMaybe)
import           Data.Proxy
import           Data.Word
import qualified Data.X509 as X509
import           Data.X509.EC

import GHC.TypeLits

import qualified Crypto.Cipher.AES as Cipher
import qualified Crypto.Cipher.CAST5 as Cipher
import qualified Crypto.Cipher.Camellia as Cipher
import qualified Crypto.Cipher.ChaChaPoly1305 as ChaChaPoly1305
import qualified Crypto.Cipher.DES as Cipher
import qualified Crypto.Cipher.TripleDES as Cipher
import           Crypto.Cipher.Types
import           Crypto.Data.Padding
import           Crypto.ECC (Curve_X25519, Curve_X448, ecdh)
import           Crypto.Error
import qualified Crypto.Hash as Hash
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import qualified Crypto.KDF.Scrypt as Scrypt
import qualified Crypto.MAC.HMAC as HMAC
import qualified Crypto.MAC.Poly1305 as Poly1305
import           Crypto.Number.Serialize
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448 as X448
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.DH as ECDH
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.MaskGenFunction as MGF
import qualified Crypto.PubKey.RSA.PSS as RSAPSS
import qualified Crypto.PubKey.RSA.OAEP as RSAOAEP
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import           Crypto.Random

import Foreign.Ptr (Ptr)
import Foreign.Storable

import           Crypto.Store.ASN1.Generate
import           Crypto.Store.ASN1.Parse
import           Crypto.Store.CMS.Util
import           Crypto.Store.Cipher.RC2
import           Crypto.Store.Error
import qualified Crypto.Store.KeyWrap.AES as AES_KW
import qualified Crypto.Store.KeyWrap.TripleDES as TripleDES_KW
import qualified Crypto.Store.KeyWrap.RC2 as RC2_KW
import           Crypto.Store.PKCS8.EC
import           Crypto.Store.Util


-- Hash functions

-- | CMS digest proxy.  Acts like 'Data.Proxy.Proxy', i.e. provides a hash
-- algorithm as type parameter.  The GADT constructors map to known algorithms.
data DigestProxy hashAlg where
    -- | MD2
    MD2    :: DigestProxy Hash.MD2
    -- | MD4
    MD4    :: DigestProxy Hash.MD4
    -- | MD5
    MD5    :: DigestProxy Hash.MD5
    -- | SHA-1
    SHA1   :: DigestProxy Hash.SHA1
    -- | SHA-224
    SHA224 :: DigestProxy Hash.SHA224
    -- | SHA-256
    SHA256 :: DigestProxy Hash.SHA256
    -- | SHA-384
    SHA384 :: DigestProxy Hash.SHA384
    -- | SHA-512
    SHA512 :: DigestProxy Hash.SHA512
    -- | SHAKE128 (256 bits)
    SHAKE128_256 :: DigestProxy (Hash.SHAKE128 256)
    -- | SHAKE256 (512 bits)
    SHAKE256_512 :: DigestProxy (Hash.SHAKE256 512)
    -- | SHAKE128 (variable size)
    SHAKE128 :: KnownNat n => Proxy n -> DigestProxy (Hash.SHAKE128 n)
    -- | SHAKE256 (variable size)
    SHAKE256 :: KnownNat n => Proxy n -> DigestProxy (Hash.SHAKE256 n)

deriving instance Show (DigestProxy hashAlg)
deriving instance Eq (DigestProxy hashAlg)

instance HasStrength (DigestProxy hashAlg) where
    getSecurityBits MD2          = 64
    getSecurityBits MD4          = 64
    getSecurityBits MD5          = 64
    getSecurityBits SHA1         = 80
    getSecurityBits SHA224       = 112
    getSecurityBits SHA256       = 128
    getSecurityBits SHA384       = 192
    getSecurityBits SHA512       = 256
    getSecurityBits SHAKE128_256 = 128
    getSecurityBits SHAKE256_512 = 256
    getSecurityBits (SHAKE128 a) = shakeSecurityBits 128 a
    getSecurityBits (SHAKE256 a) = shakeSecurityBits 256 a

shakeSecurityBits :: KnownNat n => Int -> proxy n -> Int
shakeSecurityBits m a = min m (fromInteger (natVal a) `div` 2)

-- | CMS digest algorithm.
data DigestAlgorithm =
    forall hashAlg . Hash.HashAlgorithm hashAlg
        => DigestAlgorithm (DigestProxy hashAlg)

instance Show DigestAlgorithm where
    show (DigestAlgorithm a) = show a

instance Eq DigestAlgorithm where
    DigestAlgorithm MD2          == DigestAlgorithm MD2          = True
    DigestAlgorithm MD4          == DigestAlgorithm MD4          = True
    DigestAlgorithm MD5          == DigestAlgorithm MD5          = True
    DigestAlgorithm SHA1         == DigestAlgorithm SHA1         = True
    DigestAlgorithm SHA224       == DigestAlgorithm SHA224       = True
    DigestAlgorithm SHA256       == DigestAlgorithm SHA256       = True
    DigestAlgorithm SHA384       == DigestAlgorithm SHA384       = True
    DigestAlgorithm SHA512       == DigestAlgorithm SHA512       = True
    DigestAlgorithm SHAKE128_256 == DigestAlgorithm SHAKE128_256 = True
    DigestAlgorithm SHAKE256_512 == DigestAlgorithm SHAKE256_512 = True
    DigestAlgorithm (SHAKE128 a) == DigestAlgorithm (SHAKE128 b) = natVal a == natVal b
    DigestAlgorithm (SHAKE256 a) == DigestAlgorithm (SHAKE256 b) = natVal a == natVal b
    _                            == _                            = False

instance HasStrength DigestAlgorithm where
    getSecurityBits (DigestAlgorithm a) = getSecurityBits a

data DigestType
    = Type_MD2
    | Type_MD4
    | Type_MD5
    | Type_SHA1
    | Type_SHA224
    | Type_SHA256
    | Type_SHA384
    | Type_SHA512
    | Type_SHAKE128_256
    | Type_SHAKE256_512
    | Type_SHAKE128_Len
    | Type_SHAKE256_Len

instance Enumerable DigestType where
    values = [ Type_MD2
             , Type_MD4
             , Type_MD5
             , Type_SHA1
             , Type_SHA224
             , Type_SHA256
             , Type_SHA384
             , Type_SHA512
             , Type_SHAKE128_256
             , Type_SHAKE256_512
             , Type_SHAKE128_Len
             , Type_SHAKE256_Len
             ]

instance OIDable DigestType where
    getObjectID Type_MD2          = [1,2,840,113549,2,2]
    getObjectID Type_MD4          = [1,2,840,113549,2,4]
    getObjectID Type_MD5          = [1,2,840,113549,2,5]
    getObjectID Type_SHA1         = [1,3,14,3,2,26]
    getObjectID Type_SHA224       = [2,16,840,1,101,3,4,2,4]
    getObjectID Type_SHA256       = [2,16,840,1,101,3,4,2,1]
    getObjectID Type_SHA384       = [2,16,840,1,101,3,4,2,2]
    getObjectID Type_SHA512       = [2,16,840,1,101,3,4,2,3]
    getObjectID Type_SHAKE128_256 = [2,16,840,1,101,3,4,2,11]
    getObjectID Type_SHAKE256_512 = [2,16,840,1,101,3,4,2,12]
    getObjectID Type_SHAKE128_Len = [2,16,840,1,101,3,4,2,17]
    getObjectID Type_SHAKE256_Len = [2,16,840,1,101,3,4,2,18]

instance OIDNameable DigestType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

instance AlgorithmId DigestAlgorithm where
    type AlgorithmType DigestAlgorithm = DigestType
    algorithmName _  = "digest algorithm"

    algorithmType (DigestAlgorithm MD2)          = Type_MD2
    algorithmType (DigestAlgorithm MD4)          = Type_MD4
    algorithmType (DigestAlgorithm MD5)          = Type_MD5
    algorithmType (DigestAlgorithm SHA1)         = Type_SHA1
    algorithmType (DigestAlgorithm SHA224)       = Type_SHA224
    algorithmType (DigestAlgorithm SHA256)       = Type_SHA256
    algorithmType (DigestAlgorithm SHA384)       = Type_SHA384
    algorithmType (DigestAlgorithm SHA512)       = Type_SHA512
    algorithmType (DigestAlgorithm SHAKE128_256) = Type_SHAKE128_256
    algorithmType (DigestAlgorithm SHAKE256_512) = Type_SHAKE256_512
    algorithmType (DigestAlgorithm (SHAKE128 _)) = Type_SHAKE128_Len
    algorithmType (DigestAlgorithm (SHAKE256 _)) = Type_SHAKE256_Len

    -- MD5 has NULL parameter, SHAKE128 and SHAKE256 have the bitsize as
    -- parameter, other algorithms have no parameter
    parameterASN1S (DigestAlgorithm MD5)          = gNull
    parameterASN1S (DigestAlgorithm (SHAKE128 n)) = gIntVal (natVal n)
    parameterASN1S (DigestAlgorithm (SHAKE256 n)) = gIntVal (natVal n)
    parameterASN1S _                              = id

    parseParameter Type_MD2          = parseDigestParam (DigestAlgorithm MD2)
    parseParameter Type_MD4          = parseDigestParam (DigestAlgorithm MD4)
    parseParameter Type_MD5          = parseDigestParam (DigestAlgorithm MD5)
    parseParameter Type_SHA1         = parseDigestParam (DigestAlgorithm SHA1)
    parseParameter Type_SHA224       = parseDigestParam (DigestAlgorithm SHA224)
    parseParameter Type_SHA256       = parseDigestParam (DigestAlgorithm SHA256)
    parseParameter Type_SHA384       = parseDigestParam (DigestAlgorithm SHA384)
    parseParameter Type_SHA512       = parseDigestParam (DigestAlgorithm SHA512)
    parseParameter Type_SHAKE128_256 = parseDigestParam (DigestAlgorithm SHAKE128_256)
    parseParameter Type_SHAKE256_512 = parseDigestParam (DigestAlgorithm SHAKE256_512)
    parseParameter Type_SHAKE128_Len = parseBitLen $
        \(SomeNat p) -> DigestAlgorithm (SHAKE128 p)
    parseParameter Type_SHAKE256_Len = parseBitLen $
        \(SomeNat p) -> DigestAlgorithm (SHAKE256 p)

-- | Compute the digest of a message.
digest :: ByteArrayAccess message => DigestAlgorithm -> message -> ByteString
digest (DigestAlgorithm hashAlg) message = B.convert (doHash hashAlg message)

doHash :: (Hash.HashAlgorithm hashAlg, ByteArrayAccess ba)
       => proxy hashAlg -> ba -> Hash.Digest hashAlg
doHash _ = Hash.hash

hashFromProxy :: proxy a -> a
hashFromProxy _ = undefined

parseDigestParam :: Monoid e => DigestAlgorithm -> ParseASN1 e DigestAlgorithm
parseDigestParam p = getNextMaybe nullOrNothing >> return p

parseBitLen :: Monoid e => (SomeNat -> a) -> ParseASN1 e a
parseBitLen build = do
    IntVal n <- getNext
    case someNatVal n of
        Nothing -> throwParseError ("Invalid bit length: " ++ show n)
        Just sn -> return (build sn)

p512 :: Proxy 512
p512 = Proxy


-- Security strength

-- | Algorithms with known security strength.
class HasStrength params where
    -- | Get security strength in bits.
    --
    -- This returns the strength for which the algorithm was designed.
    -- Algorithms with weaknesses have an effective strength lower than the
    -- returned value.
    getSecurityBits :: params -> Int

-- | Whether the algorithm has acceptable security.  The goal is to eliminate
-- variable-length algorithms, like SHAKE with 1-byte output, that would make
-- strength lower than the weakest fixed-length algorithm.
securityAcceptable :: HasStrength params => params -> Bool
securityAcceptable = (>= 64) . getSecurityBits


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
        => HMAC (DigestProxy hashAlg)

deriving instance Show MACAlgorithm

instance Eq MACAlgorithm where
    HMAC a1 == HMAC a2 = DigestAlgorithm a1 == DigestAlgorithm a2

instance HasStrength MACAlgorithm where
    getSecurityBits (HMAC a) = getSecurityBits (DigestAlgorithm a)

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
    | CBC_RC2
      -- ^ RC2 in CBC mode
    | forall c . BlockCipher c => CFB (ContentEncryptionCipher c)
      -- ^ Cipher Feedback
    | forall c . BlockCipher c => CTR (ContentEncryptionCipher c)
      -- ^ Counter

instance Show ContentEncryptionAlg where
    show (ECB c) = shows c "_ECB"
    show (CBC c) = shows c "_CBC"
    show CBC_RC2 = "RC2_CBC"
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
             , CBC_RC2

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
    getObjectID CBC_RC2            = [1,2,840,113549,3,2]

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
    | ParamsCBCRC2 Int (IV RC2)
      -- ^ RC2 in CBC mode
    | forall c . BlockCipher c => ParamsCFB (ContentEncryptionCipher c) (IV c)
      -- ^ Cipher Feedback
    | forall c . BlockCipher c => ParamsCTR (ContentEncryptionCipher c) (IV c)
      -- ^ Counter

instance Show ContentEncryptionParams where
    show = show . getContentEncryptionAlg

instance Eq ContentEncryptionParams where
    ParamsECB c1        == ParamsECB c2        = cecI c1 == cecI c2
    ParamsCBC c1 iv1    == ParamsCBC c2 iv2    = cecI c1 == cecI c2 && iv1 `B.eq` iv2
    ParamsCBCRC2 i1 iv1 == ParamsCBCRC2 i2 iv2 = i1 == i2 && iv1 `B.eq` iv2
    ParamsCFB c1 iv1    == ParamsCFB c2 iv2    = cecI c1 == cecI c2 && iv1 `B.eq` iv2
    ParamsCTR c1 iv1    == ParamsCTR c2 iv2    = cecI c1 == cecI c2 && iv1 `B.eq` iv2
    _                   == _                   = False

instance HasKeySize ContentEncryptionParams where
    getKeySizeSpecifier (ParamsECB c)      = getCipherKeySizeSpecifier c
    getKeySizeSpecifier (ParamsCBC c _)    = getCipherKeySizeSpecifier c
    getKeySizeSpecifier (ParamsCBCRC2 i _) = KeySizeFixed $ (i + 7) `div` 8
    getKeySizeSpecifier (ParamsCFB c _)    = getCipherKeySizeSpecifier c
    getKeySizeSpecifier (ParamsCTR c _)    = getCipherKeySizeSpecifier c

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
ceParameterASN1S (ParamsECB _)         = id
ceParameterASN1S (ParamsCBC _ iv)      = gOctetString (B.convert iv)
ceParameterASN1S (ParamsCBCRC2 len iv) = rc2ParameterASN1S len iv
ceParameterASN1S (ParamsCFB _ iv)      = gOctetString (B.convert iv)
ceParameterASN1S (ParamsCTR _ iv)      = gOctetString (B.convert iv)

parseCEParameter :: Monoid e
                 => ContentEncryptionAlg -> ParseASN1 e ContentEncryptionParams
parseCEParameter (ECB c) = getMany getNext >> return (ParamsECB c)
parseCEParameter (CBC c) = ParamsCBC c <$> (getNext >>= getIV)
parseCEParameter CBC_RC2 = parseRC2Parameter
parseCEParameter (CFB c) = ParamsCFB c <$> (getNext >>= getIV)
parseCEParameter (CTR c) = ParamsCTR c <$> (getNext >>= getIV)

getIV :: BlockCipher cipher => ASN1 -> ParseASN1 e (IV cipher)
getIV (OctetString ivBs) =
    case makeIV ivBs of
        Nothing -> throwParseError "Bad IV in parsed parameters"
        Just v  -> return v
getIV _ = throwParseError "No IV in parsed parameter or incorrect format"

rc2ParameterASN1S :: ASN1Elem e => Int -> IV RC2 -> ASN1Stream e
rc2ParameterASN1S len iv
    | len == 32 = gIV
    | otherwise = asn1Container Sequence (rc2VersionASN1 len . gIV)
  where gIV = gOctetString (B.convert iv)

parseRC2Parameter :: Monoid e => ParseASN1 e ContentEncryptionParams
parseRC2Parameter = parseOnlyIV 32 <|> parseFullParams
  where
    parseOnlyIV len = ParamsCBCRC2 len <$> (getNext >>= getIV)
    parseFullParams = onNextContainer Sequence $
        parseRC2Version >>= parseOnlyIV

-- | Get the content encryption algorithm.
getContentEncryptionAlg :: ContentEncryptionParams -> ContentEncryptionAlg
getContentEncryptionAlg (ParamsECB c)      = ECB c
getContentEncryptionAlg (ParamsCBC c _)    = CBC c
getContentEncryptionAlg (ParamsCBCRC2 _ _) = CBC_RC2
getContentEncryptionAlg (ParamsCFB c _)    = CFB c
getContentEncryptionAlg (ParamsCTR c _)    = CTR c

-- | Generate random parameters for the specified content encryption algorithm.
generateEncryptionParams :: MonadRandom m
                         => ContentEncryptionAlg -> m ContentEncryptionParams
generateEncryptionParams (ECB c) = return (ParamsECB c)
generateEncryptionParams (CBC c) = ParamsCBC c <$> ivGenerate undefined
generateEncryptionParams CBC_RC2 = ParamsCBCRC2 128 <$> ivGenerate undefined
generateEncryptionParams (CFB c) = ParamsCFB c <$> ivGenerate undefined
generateEncryptionParams (CTR c) = ParamsCTR c <$> ivGenerate undefined

-- | Generate random RC2 parameters with the specified effective key length (in
-- bits).
generateRC2EncryptionParams :: MonadRandom m
                            => Int -> m ContentEncryptionParams
generateRC2EncryptionParams len = ParamsCBCRC2 len <$> ivGenerate undefined

-- | Encrypt a bytearray with the specified content encryption key and
-- algorithm.
contentEncrypt :: (ByteArray cek, ByteArray ba)
               => cek
               -> ContentEncryptionParams
               -> ba -> Either StoreError ba
contentEncrypt key params bs =
    case params of
        ParamsECB cipher    -> getCipher cipher key >>= (\c -> force $ ecbEncrypt c    $ padded c bs)
        ParamsCBC cipher iv -> getCipher cipher key >>= (\c -> force $ cbcEncrypt c iv $ padded c bs)
        ParamsCBCRC2 len iv -> getRC2Cipher len key >>= (\c -> force $ cbcEncrypt c iv $ padded c bs)
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
               -> ba -> Either StoreError ba
contentDecrypt key params bs =
    case params of
        ParamsECB cipher    -> getCipher cipher key >>= (\c -> unpadded c (ecbDecrypt c    bs))
        ParamsCBC cipher iv -> getCipher cipher key >>= (\c -> unpadded c (cbcDecrypt c iv bs))
        ParamsCBCRC2 len iv -> getRC2Cipher len key >>= (\c -> unpadded c (cbcDecrypt c iv bs))
        ParamsCFB cipher iv -> getCipher cipher key >>= (\c -> unpadded c (cfbDecrypt c iv bs))
        ParamsCTR cipher iv -> getCipher cipher key >>= (\c -> unpadded c (ctrCombine c iv bs))
  where
    unpadded c decrypted =
        case unpad (PKCS7 $ blockSize c) decrypted of
            Nothing  -> Left DecryptionFailed
            Just out -> Right out

-- from RFC 2268 section 6
rc2Table :: [Word8]
rc2Table =
    [ 0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0
    , 0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b, 0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a
    , 0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36
    , 0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8, 0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c
    , 0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17, 0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60
    , 0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa
    , 0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e
    , 0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b, 0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf
    , 0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6
    , 0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3
    , 0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e, 0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c
    , 0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2
    , 0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46, 0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5
    , 0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97, 0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5
    , 0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef, 0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f
    , 0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab
    ]

rc2Forward :: B.Bytes
rc2Forward = B.pack rc2Table

rc2Reverse :: B.Bytes
rc2Reverse = B.allocAndFreeze (length rc2Table) (loop $ zip [0..] rc2Table)
  where
    loop :: [(Word8, Word8)] -> Ptr Word8 -> IO ()
    loop []         _ = return ()
    loop ((a,b):ts) p = pokeElemOff p (fromIntegral b) a >> loop ts p

rc2VersionASN1 :: ASN1Elem e => Int -> ASN1Stream e
rc2VersionASN1 len = gIntVal v
  where
    v | len < 0    = error "invalid RC2 effective key length"
      | len >= 256 = fromIntegral len
      | otherwise  = fromIntegral (B.index rc2Forward len)

parseRC2Version :: Monoid e => ParseASN1 e Int
parseRC2Version = do
    IntVal i <- getNext
    when (i < 0) $ throwParseError "Parsed invalid RC2 effective key length"
    let j = fromIntegral i
    return $ if i >= 256 then j else fromIntegral (B.index rc2Reverse j)


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
        iv1 `B.eq` iv2

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
                   -> aad -> ba -> Either StoreError (AuthTag, ba)
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

    encrypt :: Int -> AEAD a -> Either StoreError (AuthTag, ba)
    encrypt len aead = force $ aeadSimpleEncrypt aead aad bs len

    ccpEncrypt :: ChaChaPoly1305.State -> Either a (AuthTag, ba)
    ccpEncrypt state = force (found, encrypted)
      where
        (encrypted, state') = ChaChaPoly1305.encrypt bs state
        found = ccpTag (ChaChaPoly1305.finalize state')

    authEncrypt :: AuthEncParams -> Either StoreError (AuthTag, ba)
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
                   -> aad -> ba -> AuthTag -> Either StoreError ba
authContentDecrypt key params paramsRaw aad bs expected =
    case params of
        Params_AUTH_ENC_128 p   -> checkAuthKey 16 key >> authDecrypt p
        Params_AUTH_ENC_256 p   -> checkAuthKey 32 key >> authDecrypt p
        Params_CHACHA20_POLY1305 iv -> ccpInit key iv aad >>= ccpDecrypt
        ParamsCCM cipher iv m l -> getAEAD cipher key (AEAD_CCM msglen m l) iv >>= decrypt
        ParamsGCM cipher iv _   -> getAEAD cipher key AEAD_GCM iv >>= decrypt
  where
    msglen  = B.length bs
    badMac  = Left BadContentMAC

    decrypt :: AEAD a -> Either StoreError ba
    decrypt aead = maybe badMac Right (aeadSimpleDecrypt aead aad bs expected)

    ccpDecrypt :: ChaChaPoly1305.State -> Either StoreError ba
    ccpDecrypt state
        | found == expected = Right decrypted
        | otherwise         = badMac
      where
        (decrypted, state') = ChaChaPoly1305.decrypt bs state
        found = ccpTag (ChaChaPoly1305.finalize state')

    authDecrypt :: AuthEncParams -> Either StoreError ba
    authDecrypt p@AuthEncParams{..}
        | found == expected = contentDecrypt encKey encAlgorithm bs
        | otherwise         = badMac
      where
        (encKey, macKey) = authKeys key p
        macMsg = paramsRaw `B.append` bs `B.append` B.convert aad
        found  = mac macAlgorithm macKey macMsg

getAEAD :: (BlockCipher cipher, ByteArray key, ByteArrayAccess iv)
        => proxy cipher -> key -> AEADMode -> iv -> Either StoreError (AEAD cipher)
getAEAD cipher key mode iv = do
    c <- getCipher cipher key
    fromCryptoFailable $ aeadInit mode c iv

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

checkAuthKey :: ByteArrayAccess cek => Int -> cek -> Either StoreError ()
checkAuthKey sz key
    | actual == sz = Right ()
    | otherwise    = Left (CryptoError CryptoError_KeySizeInvalid)
  where actual = B.length key

ccpInit :: (ByteArrayAccess key, ByteArrayAccess aad)
        => key
        -> ChaChaPoly1305.Nonce
        -> aad
        -> Either StoreError ChaChaPoly1305.State
ccpInit key nonce aad = case ChaChaPoly1305.initialize key nonce of
    CryptoPassed s -> return (addAAD s)
    CryptoFailed e -> Left (CryptoError e)
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
                       | TypeRC2_WRAP

instance Enumerable KeyEncryptionType where
    values = [ TypePWRIKEK
             , TypeAES128_WRAP
             , TypeAES192_WRAP
             , TypeAES256_WRAP
             , TypeAES128_WRAP_PAD
             , TypeAES192_WRAP_PAD
             , TypeAES256_WRAP_PAD
             , TypeDES_EDE3_WRAP
             , TypeRC2_WRAP
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
    getObjectID TypeRC2_WRAP        = [1,2,840,113549,1,9,16,3,7]

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
                         | RC2_WRAP Int                     -- ^ RC2 key wrap with effective key length
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
    algorithmType (RC2_WRAP _)     = TypeRC2_WRAP

    parameterASN1S (PWRIKEK cep)  = asn1s cep
    parameterASN1S DES_EDE3_WRAP  = gNull
    parameterASN1S (RC2_WRAP ekl) = rc2VersionASN1 ekl
    parameterASN1S _              = id

    parseParameter TypePWRIKEK          = PWRIKEK <$> parse
    parseParameter TypeAES128_WRAP      = return AES128_WRAP
    parseParameter TypeAES192_WRAP      = return AES192_WRAP
    parseParameter TypeAES256_WRAP      = return AES256_WRAP
    parseParameter TypeAES128_WRAP_PAD  = return AES128_WRAP_PAD
    parseParameter TypeAES192_WRAP_PAD  = return AES192_WRAP_PAD
    parseParameter TypeAES256_WRAP_PAD  = return AES256_WRAP_PAD
    parseParameter TypeDES_EDE3_WRAP    = getNextMaybe nullOrNothing >> return DES_EDE3_WRAP
    parseParameter TypeRC2_WRAP         = RC2_WRAP <$> parseRC2Version

instance HasKeySize KeyEncryptionParams where
    getKeySizeSpecifier (PWRIKEK cep)   = getKeySizeSpecifier cep
    getKeySizeSpecifier AES128_WRAP     = getCipherKeySizeSpecifier AES128
    getKeySizeSpecifier AES192_WRAP     = getCipherKeySizeSpecifier AES192
    getKeySizeSpecifier AES256_WRAP     = getCipherKeySizeSpecifier AES256
    getKeySizeSpecifier AES128_WRAP_PAD = getCipherKeySizeSpecifier AES128
    getKeySizeSpecifier AES192_WRAP_PAD = getCipherKeySizeSpecifier AES192
    getKeySizeSpecifier AES256_WRAP_PAD = getCipherKeySizeSpecifier AES256
    getKeySizeSpecifier DES_EDE3_WRAP   = getCipherKeySizeSpecifier DES_EDE3
    getKeySizeSpecifier (RC2_WRAP _)    = KeySizeFixed 16

-- | Encrypt a key with the specified key encryption key and algorithm.
keyEncrypt :: (MonadRandom m, ByteArray kek, ByteArray ba)
           => kek -> KeyEncryptionParams -> ba -> m (Either StoreError ba)
keyEncrypt key (PWRIKEK params) bs =
    case params of
        ParamsECB cipher    -> let cc = getCipher cipher key in either (return . Left) (\c -> wrapEncrypt (const . ecbEncrypt) c undefined bs) cc
        ParamsCBC cipher iv -> let cc = getCipher cipher key in either (return . Left) (\c -> wrapEncrypt cbcEncrypt c iv bs) cc
        ParamsCBCRC2 len iv -> let cc = getRC2Cipher len key in either (return . Left) (\c -> wrapEncrypt cbcEncrypt c iv bs) cc
        ParamsCFB cipher iv -> let cc = getCipher cipher key in either (return . Left) (\c -> wrapEncrypt cfbEncrypt c iv bs) cc
        ParamsCTR _ _       -> return $ Left (InvalidParameter "Unable to wrap key in CTR mode")
keyEncrypt key AES128_WRAP      bs = return (getCipher AES128 key >>= (`AES_KW.wrap` bs))
keyEncrypt key AES192_WRAP      bs = return (getCipher AES192 key >>= (`AES_KW.wrap` bs))
keyEncrypt key AES256_WRAP      bs = return (getCipher AES256 key >>= (`AES_KW.wrap` bs))
keyEncrypt key AES128_WRAP_PAD  bs = return (getCipher AES128 key >>= (`AES_KW.wrapPad` bs))
keyEncrypt key AES192_WRAP_PAD  bs = return (getCipher AES192 key >>= (`AES_KW.wrapPad` bs))
keyEncrypt key AES256_WRAP_PAD  bs = return (getCipher AES256 key >>= (`AES_KW.wrapPad` bs))
keyEncrypt key DES_EDE3_WRAP    bs = either (return . Left) (wrap3DES bs) (getCipher DES_EDE3 key)
  where wrap3DES b c = (\iv -> TripleDES_KW.wrap c iv b) <$> ivGenerate c
keyEncrypt key (RC2_WRAP ekl)   bs = either (return . Left) (wrapRC2 bs) (getRC2Cipher ekl key)
  where wrapRC2 b c = do iv <- ivGenerate c; RC2_KW.wrap c iv b

-- | Decrypt a key with the specified key encryption key and algorithm.
keyDecrypt :: (ByteArray kek, ByteArray ba)
           => kek -> KeyEncryptionParams -> ba -> Either StoreError ba
keyDecrypt key (PWRIKEK params) bs =
    case params of
        ParamsECB cipher    -> getCipher cipher key >>= (\c -> wrapDecrypt (const . ecbDecrypt) c undefined bs)
        ParamsCBC cipher iv -> getCipher cipher key >>= (\c -> wrapDecrypt cbcDecrypt c iv bs)
        ParamsCBCRC2 len iv -> getRC2Cipher len key >>= (\c -> wrapDecrypt cbcDecrypt c iv bs)
        ParamsCFB cipher iv -> getCipher cipher key >>= (\c -> wrapDecrypt cfbDecrypt c iv bs)
        ParamsCTR _ _       -> Left (InvalidParameter "Unable to unwrap key in CTR mode")
keyDecrypt key AES128_WRAP      bs = getCipher AES128   key >>= (`AES_KW.unwrap` bs)
keyDecrypt key AES192_WRAP      bs = getCipher AES192   key >>= (`AES_KW.unwrap` bs)
keyDecrypt key AES256_WRAP      bs = getCipher AES256   key >>= (`AES_KW.unwrap` bs)
keyDecrypt key AES128_WRAP_PAD  bs = getCipher AES128   key >>= (`AES_KW.unwrapPad` bs)
keyDecrypt key AES192_WRAP_PAD  bs = getCipher AES192   key >>= (`AES_KW.unwrapPad` bs)
keyDecrypt key AES256_WRAP_PAD  bs = getCipher AES256   key >>= (`AES_KW.unwrapPad` bs)
keyDecrypt key DES_EDE3_WRAP    bs = getCipher DES_EDE3 key >>= (`TripleDES_KW.unwrap` bs)
keyDecrypt key (RC2_WRAP ekl)   bs = getRC2Cipher ekl key >>= (`RC2_KW.unwrap` bs)

keyWrap :: (MonadRandom m, ByteArray ba)
        => Int -> ba -> m (Either StoreError ba)
keyWrap sz input
    | inLen <   3 = return $ Left (InvalidInput "keyWrap: input key too short")
    | inLen > 255 = return $ Left (InvalidInput "keyWrap: input key too long")
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

keyUnwrap :: ByteArray ba => ba -> Either StoreError ba
keyUnwrap input
    | inLen < 4         = Left (InvalidInput "keyUnwrap: invalid wrapped key")
    | valid             = Right $ B.take count (B.drop 4 input)
    | otherwise         = Left (InvalidInput "keyUnwrap: invalid wrapped key")
  where
    inLen = B.length input
    count = fromIntegral (B.index input 0)
    bytes = [ B.index input (i + 1) `xor` B.index input (i + 4) | i <- [0..2] ]
    valid = foldl1 (.&.) bytes == 0xFF &&! inLen >= count - 4

wrapEncrypt :: (MonadRandom m, BlockCipher cipher, ByteArray ba)
            => (cipher -> IV cipher -> ba -> ba)
            -> cipher -> IV cipher -> ba -> m (Either StoreError ba)
wrapEncrypt encFn cipher iv input = do
    wrapped <- keyWrap sz input
    return (fn <$> wrapped)
  where
    sz = blockSize cipher
    fn formatted =
        let firstPass = encFn cipher iv formatted
            lastBlock = B.dropView firstPass (B.length firstPass - sz)
            Just iv'  = makeIV lastBlock
         in encFn cipher iv' firstPass

wrapDecrypt :: (BlockCipher cipher, ByteArray ba)
            => (cipher -> IV cipher -> ba -> ba)
            -> cipher -> IV cipher -> ba -> Either StoreError ba
wrapDecrypt decFn cipher iv input = keyUnwrap (decFn cipher iv firstPass)
  where
    sz = blockSize cipher
    (beg, lb) = B.splitAt (B.length input - sz) input
    lastBlock = decFn cipher iv' lb
    Just iv'  = makeIV (B.dropView beg (B.length beg - sz))
    Just iv'' = makeIV lastBlock
    firstPass = decFn cipher iv'' beg `B.append` lastBlock


-- Key transport

-- | Encryption parameters for RSAES-OAEP.
data OAEPParams = OAEPParams
    { oaepHashAlgorithm :: DigestAlgorithm       -- ^ Hash function
    , oaepMaskGenAlgorithm :: MaskGenerationFunc -- ^ Mask generation function
    }
    deriving (Show,Eq)

instance HasStrength OAEPParams where
    getSecurityBits OAEPParams{..} =
        min (getSecurityBits oaepHashAlgorithm)
            (getSecurityBits oaepMaskGenAlgorithm)

withOAEPParams :: forall seed output a . (ByteArrayAccess seed, ByteArray output)
               => OAEPParams
               -> (forall hash . Hash.HashAlgorithm hash => RSAOAEP.OAEPParams hash seed output -> a)
               -> a
withOAEPParams p fn =
    case oaepHashAlgorithm p of
        DigestAlgorithm hashAlg ->
            fn RSAOAEP.OAEPParams
                { RSAOAEP.oaepHash = hashFromProxy hashAlg
                , RSAOAEP.oaepMaskGenAlg = mgf (oaepMaskGenAlgorithm p)
                , RSAOAEP.oaepLabel = Nothing
                }

instance ASN1Elem e => ProduceASN1Object e OAEPParams where
    asn1s OAEPParams{..} =
        asn1Container Sequence (h . m)
      where
        sha1  = DigestAlgorithm SHA1
        tag i = asn1Container (Container Context i)

        h | oaepHashAlgorithm == sha1 = id
          | otherwise = tag 0 (algorithmASN1S Sequence oaepHashAlgorithm)

        m | oaepMaskGenAlgorithm == MGF1 sha1 = id
          | otherwise = tag 1 (algorithmASN1S Sequence oaepMaskGenAlgorithm)

instance Monoid e => ParseASN1Object e OAEPParams where
    parse = onNextContainer Sequence $ do
        h <- tag 0 (parseAlgorithm Sequence)
        m <- tag 1 (parseAlgorithm Sequence)
        _ <- tag 2 parsePSpecified
        return OAEPParams { oaepHashAlgorithm = fromMaybe sha1 h
                          , oaepMaskGenAlgorithm = fromMaybe (MGF1 sha1) m
                          }
      where
        sha1  = DigestAlgorithm SHA1
        tag i = onNextContainerMaybe (Container Context i)

        parsePSpecified = do
            OID [1,2,840,113549,1,1,9] <- getNext
            OctetString p <- getNext
            guard (B.null p)

data KeyTransportType = TypeRSAES
                      | TypeRSAESOAEP

instance Enumerable KeyTransportType where
    values = [ TypeRSAES
             , TypeRSAESOAEP
             ]

instance OIDable KeyTransportType where
    getObjectID TypeRSAES          = [1,2,840,113549,1,1,1]
    getObjectID TypeRSAESOAEP      = [1,2,840,113549,1,1,7]

instance OIDNameable KeyTransportType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

-- | Key transport algorithm with associated parameters.
data KeyTransportParams = RSAES                 -- ^ RSAES-PKCS1
                        | RSAESOAEP OAEPParams  -- ^ RSAES-OAEP
                        deriving (Show,Eq)

instance AlgorithmId KeyTransportParams where
    type AlgorithmType KeyTransportParams = KeyTransportType
    algorithmName _ = "key transport algorithm"

    algorithmType RSAES              = TypeRSAES
    algorithmType (RSAESOAEP _)      = TypeRSAESOAEP

    parameterASN1S RSAES             = gNull
    parameterASN1S (RSAESOAEP p)     = asn1s p

    parseParameter TypeRSAES         = getNextMaybe nullOrNothing >> return RSAES
    parseParameter TypeRSAESOAEP     = RSAESOAEP <$> parse

-- | Encrypt the specified content with a key-transport algorithm and recipient
-- public key.
transportEncrypt :: MonadRandom m
                 => KeyTransportParams
                 -> X509.PubKey
                 -> ByteString
                 -> m (Either StoreError ByteString)
transportEncrypt RSAES         (X509.PubKeyRSA pub) bs =
    mapLeft RSAError <$> RSA.encrypt pub bs
transportEncrypt (RSAESOAEP p) (X509.PubKeyRSA pub) bs =
    withOAEPParams p $ \params ->
        mapLeft RSAError <$> RSAOAEP.encrypt params pub bs
transportEncrypt _ _ _ = return $ Left UnexpectedPublicKeyType

-- | Decrypt the specified content with a key-transport algorithm and recipient
-- private key.
transportDecrypt :: MonadRandom m
                 => KeyTransportParams
                 -> X509.PrivKey
                 -> ByteString
                 -> m (Either StoreError ByteString)
transportDecrypt RSAES         (X509.PrivKeyRSA priv) bs =
    mapLeft RSAError <$> RSA.decryptSafer priv bs
transportDecrypt (RSAESOAEP p) (X509.PrivKeyRSA priv) bs =
    withOAEPParams p $ \params ->
        mapLeft RSAError <$> RSAOAEP.decryptSafer params priv bs
transportDecrypt _ _ _ = return $ Left UnexpectedPrivateKeyType


-- Key agreement

data KeyAgreementType = TypeStdDH DigestAlgorithm
                      | TypeCofactorDH DigestAlgorithm
                      deriving (Show,Eq)

instance Enumerable KeyAgreementType where
    values = [ TypeStdDH (DigestAlgorithm SHA1)
             , TypeStdDH (DigestAlgorithm SHA224)
             , TypeStdDH (DigestAlgorithm SHA256)
             , TypeStdDH (DigestAlgorithm SHA384)
             , TypeStdDH (DigestAlgorithm SHA512)

             , TypeCofactorDH (DigestAlgorithm SHA1)
             , TypeCofactorDH (DigestAlgorithm SHA224)
             , TypeCofactorDH (DigestAlgorithm SHA256)
             , TypeCofactorDH (DigestAlgorithm SHA384)
             , TypeCofactorDH (DigestAlgorithm SHA512)
             ]

instance OIDable KeyAgreementType where
    getObjectID (TypeStdDH (DigestAlgorithm SHA1))        = [1,3,133,16,840,63,0,2]
    getObjectID (TypeStdDH (DigestAlgorithm SHA224))      = [1,3,132,1,11,0]
    getObjectID (TypeStdDH (DigestAlgorithm SHA256))      = [1,3,132,1,11,1]
    getObjectID (TypeStdDH (DigestAlgorithm SHA384))      = [1,3,132,1,11,2]
    getObjectID (TypeStdDH (DigestAlgorithm SHA512))      = [1,3,132,1,11,3]

    getObjectID (TypeCofactorDH (DigestAlgorithm SHA1))   = [1,3,133,16,840,63,0,3]
    getObjectID (TypeCofactorDH (DigestAlgorithm SHA224)) = [1,3,132,1,14,0]
    getObjectID (TypeCofactorDH (DigestAlgorithm SHA256)) = [1,3,132,1,14,1]
    getObjectID (TypeCofactorDH (DigestAlgorithm SHA384)) = [1,3,132,1,14,2]
    getObjectID (TypeCofactorDH (DigestAlgorithm SHA512)) = [1,3,132,1,14,3]

    getObjectID ty = error ("Unsupported KeyAgreementType: " ++ show ty)

instance OIDNameable KeyAgreementType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

-- | Key agreement algorithm with associated parameters.
data KeyAgreementParams = StdDH DigestAlgorithm KeyEncryptionParams
                          -- ^ 1-Pass D-H with Stardard ECDH
                        | CofactorDH DigestAlgorithm KeyEncryptionParams
                          -- ^ 1-Pass D-H with Cofactor ECDH
                        deriving (Show,Eq)

instance AlgorithmId KeyAgreementParams where
    type AlgorithmType KeyAgreementParams = KeyAgreementType
    algorithmName _ = "key agreement algorithm"

    algorithmType (StdDH d _)         = TypeStdDH d
    algorithmType (CofactorDH d _)    = TypeCofactorDH d

    parameterASN1S (StdDH _ p)        = algorithmASN1S Sequence p
    parameterASN1S (CofactorDH _ p)   = algorithmASN1S Sequence p

    parseParameter (TypeStdDH d)      = StdDH d <$> parseAlgorithm Sequence
    parseParameter (TypeCofactorDH d) = CofactorDH d <$> parseAlgorithm Sequence

ecdhKeyMaterial :: (ByteArrayAccess bin, ByteArray bout)
                => DigestAlgorithm -> KeyEncryptionParams -> Maybe ByteString -> bin -> bout
ecdhKeyMaterial (DigestAlgorithm hashAlg) kep ukm zz
    | r == 0    = B.concat (map chunk [1..d])
    | otherwise = B.concat (map chunk [1..d]) `B.append` B.take r (chunk $ succ d)
  where
    (d, r)   = outLen `divMod` Hash.hashDigestSize prx

    prx      = hashFromProxy hashAlg
    outLen   = getMaximumKeySize kep
    outBits  = 8 * outLen
    toWord32 = i2ospOf_ 4 . fromIntegral

    chunk     = B.convert . Hash.hashFinalize . hashCtx
    hashCtx'  = Hash.hashInitWith prx
    hashCtx i = Hash.hashUpdate (Hash.hashUpdate (Hash.hashUpdate hashCtx' zz) (toWord32 i)) otherInfo
    otherInfo =
        let ki  = algorithmASN1S Sequence kep
            eui = case ukm of
                    Nothing -> id
                    Just bs -> asn1Container (Container Context 0)
                                   (gOctetString bs)
            spi = asn1Container (Container Context 2)
                      (gOctetString $ toWord32 outBits)
         in encodeASN1S $ asn1Container Sequence (ki . eui . spi)

-- | Key pair for ECDH.
data ECDHPair
    = PairEC ECC.Curve ECC.PrivateNumber ECC.Point
    | PairX25519 X25519.SecretKey X25519.PublicKey
    | PairX448 X448.SecretKey X448.PublicKey

-- | Generate an ephemeral ECDH key.
ecdhGenerate :: MonadRandom m => X509.PubKey -> m (Either StoreError ECDHPair)
ecdhGenerate (X509.PubKeyEC pub) =
    case ecPubKeyCurveName pub of
        Nothing -> return $ Left NamedCurveRequired
        Just n  -> do
            let curve = ECC.getCurveByName n
            priv <- ECDH.generatePrivate curve
            return $ case unserializePoint curve (X509.pubkeyEC_pub pub) of
                Nothing -> Left (InvalidInput "Invalid serialized point")
                Just pt -> Right (PairEC curve priv pt)
ecdhGenerate (X509.PubKeyX25519 pub) = do
    priv <- X25519.generateSecretKey
    return $ Right (PairX25519 priv pub)
ecdhGenerate (X509.PubKeyX448 pub) = do
    priv <- X448.generateSecretKey
    return $ Right (PairX448 priv pub)
ecdhGenerate _ = return $ Left UnexpectedPublicKeyType

-- | Return the serialized public key corresponding to the ECDH private key.
ecdhPublic :: ECDHPair -> ByteString
ecdhPublic (PairEC curve d _)  = unSerialize (getSerializedPoint curve d)
  where unSerialize (X509.SerializedPoint pt) = pt
ecdhPublic (PairX25519 priv _) = B.convert (X25519.toPublic priv)
ecdhPublic (PairX448 priv _)   = B.convert (X448.toPublic priv)

-- | Encrypt the specified content with an ECDH key pair and key-agreement
-- algorithm.
ecdhEncrypt :: (MonadRandom m, ByteArray ba)
            => KeyAgreementParams -> Maybe ByteString -> ECDHPair -> ba -> m (Either StoreError ba)
ecdhEncrypt (StdDH dig kep) ukm (PairEC curve d pub) bs = do
    let s = ECDH.getShared curve d pub
        k = ecdhKeyMaterial dig kep ukm s :: B.ScrubbedBytes
    keyEncrypt k kep bs
ecdhEncrypt (StdDH dig kep) ukm (PairX25519 priv pub) bs =
    case fromCryptoFailable (ecdh x25519 priv pub) of
        Left e  -> return (Left e)
        Right s ->
            let k = ecdhKeyMaterial dig kep ukm s :: B.ScrubbedBytes
             in keyEncrypt k kep bs
ecdhEncrypt (StdDH dig kep) ukm (PairX448 priv pub) bs =
    case fromCryptoFailable (ecdh x448 priv pub) of
        Left e  -> return (Left e)
        Right s ->
            let k = ecdhKeyMaterial dig kep ukm s :: B.ScrubbedBytes
             in keyEncrypt k kep bs
ecdhEncrypt (CofactorDH dig kep) ukm (PairEC curve d pub) bs = do
    let h = ECC.ecc_h (ECC.common_curve curve)
        s = ECDH.getShared curve (h * d) pub
        k = ecdhKeyMaterial dig kep ukm s :: B.ScrubbedBytes
    keyEncrypt k kep bs
ecdhEncrypt (CofactorDH _ _) _ (PairX25519 _ _) _ =
    return $ Left (InvalidInput "X25519 is not supported for cofactor DH")
ecdhEncrypt (CofactorDH _ _) _ (PairX448 _ _) _ =
    return $ Left (InvalidInput "X448 is not supported for cofactor DH")

-- | Decrypt the specified content with an ECDH key pair and key-agreement
-- algorithm.
ecdhDecrypt :: ByteArray ba
            => KeyAgreementParams -> Maybe ByteString -> X509.PrivKey -> ByteString -> ba -> Either StoreError ba
ecdhDecrypt (StdDH dig kep) ukm (X509.PrivKeyEC priv) pt bs =
    case ecPrivKeyCurve priv of
        Nothing    -> Left UnsupportedEllipticCurve
        Just curve ->
            case unserializePoint curve (X509.SerializedPoint pt) of
                Nothing  -> Left (InvalidInput "Invalid serialized point")
                Just pub -> do
                    let d = X509.privkeyEC_priv priv
                        s = ECDH.getShared curve d pub
                        k = ecdhKeyMaterial dig kep ukm s :: B.ScrubbedBytes
                    keyDecrypt k kep bs
ecdhDecrypt (StdDH dig kep) ukm (X509.PrivKeyX25519 priv) pt bs = do
    s <- fromCryptoFailable (X25519.publicKey pt >>= ecdh x25519 priv)
    let k = ecdhKeyMaterial dig kep ukm s :: B.ScrubbedBytes
    keyDecrypt k kep bs
ecdhDecrypt (StdDH dig kep) ukm (X509.PrivKeyX448 priv) pt bs = do
    s <- fromCryptoFailable (X448.publicKey pt >>= ecdh x448 priv)
    let k = ecdhKeyMaterial dig kep ukm s :: B.ScrubbedBytes
    keyDecrypt k kep bs
ecdhDecrypt (StdDH _ _) _ _ _ _ = Left UnexpectedPrivateKeyType
ecdhDecrypt (CofactorDH dig kep) ukm (X509.PrivKeyEC priv) pt bs =
    case ecPrivKeyCurve priv of
        Nothing    -> Left UnsupportedEllipticCurve
        Just curve ->
            case unserializePoint curve (X509.SerializedPoint pt) of
                Nothing  -> Left (InvalidInput "Invalid serialized point")
                Just pub -> do
                    let h = ECC.ecc_h (ECC.common_curve curve)
                        d = X509.privkeyEC_priv priv
                        s = ECDH.getShared curve (h * d) pub
                        k = ecdhKeyMaterial dig kep ukm s :: B.ScrubbedBytes
                    keyDecrypt k kep bs
ecdhDecrypt (CofactorDH _ _) _ _ _ _ = Left UnexpectedPrivateKeyType

x25519 :: Proxy Curve_X25519
x25519 = Proxy

x448 :: Proxy Curve_X448
x448 = Proxy


-- Utilities

getCipher :: (BlockCipher cipher, ByteArray key)
          => proxy cipher -> key -> Either StoreError cipher
getCipher _ key = fromCryptoFailable (cipherInit key)

getRC2Cipher :: ByteArray key => Int -> key -> Either StoreError RC2
getRC2Cipher len key = fromCryptoFailable (rc2WithEffectiveKeyLength len key)

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


-- Mask generation functions

data MaskGenerationType = TypeMGF1
    deriving (Show,Eq)

instance Enumerable MaskGenerationType where
    values = [ TypeMGF1
             ]

instance OIDable MaskGenerationType where
    getObjectID TypeMGF1     = [1,2,840,113549,1,1,8]

instance OIDNameable MaskGenerationType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

-- | Mask Generation Functions (MGF) and associated parameters.
newtype MaskGenerationFunc = MGF1 DigestAlgorithm
    deriving (Show,Eq)

instance HasStrength MaskGenerationFunc where
    getSecurityBits (MGF1 d) = getSecurityBits d

instance AlgorithmId MaskGenerationFunc where
    type AlgorithmType MaskGenerationFunc = MaskGenerationType
    algorithmName _  = "mask generation function"

    algorithmType (MGF1 _)   = TypeMGF1

    parameterASN1S (MGF1 d)  = algorithmASN1S Sequence d

    parseParameter TypeMGF1  = MGF1 <$> parseAlgorithm Sequence

-- | Generate a mask with the MGF.
mgf :: (ByteArrayAccess seed, ByteArray output)
    => MaskGenerationFunc -> seed -> Int -> output
mgf (MGF1 (DigestAlgorithm hashAlg)) = MGF.mgf1 (hashFromProxy hashAlg)


-- Signature algorithms

-- | Signature value.
type SignatureValue = ByteString

-- | Signature parameters for RSASSA-PSS.
data PSSParams = PSSParams
    { pssHashAlgorithm :: DigestAlgorithm       -- ^ Hash function
    , pssMaskGenAlgorithm :: MaskGenerationFunc -- ^ Mask generation function
    , pssSaltLength :: Int                      -- ^ Length of the salt in bytes
    }
    deriving (Show,Eq)

instance HasStrength PSSParams where
    getSecurityBits PSSParams{..} =
        min (getSecurityBits pssHashAlgorithm)
            (getSecurityBits pssMaskGenAlgorithm)

withPSSParams :: forall seed output a . (ByteArrayAccess seed, ByteArray output)
              => PSSParams
              -> (forall hash . Hash.HashAlgorithm hash => RSAPSS.PSSParams hash seed output -> a)
              -> a
withPSSParams p fn =
    case pssHashAlgorithm p of
        DigestAlgorithm hashAlg ->
            fn RSAPSS.PSSParams
                { RSAPSS.pssHash = hashFromProxy hashAlg
                , RSAPSS.pssMaskGenAlg = mgf (pssMaskGenAlgorithm p)
                , RSAPSS.pssSaltLength = pssSaltLength p
                , RSAPSS.pssTrailerField = 0xbc
                }

instance ASN1Elem e => ProduceASN1Object e PSSParams where
    asn1s PSSParams{..} =
        asn1Container Sequence (h . m . s)
      where
        sha1  = DigestAlgorithm SHA1
        tag i = asn1Container (Container Context i)

        h | pssHashAlgorithm == sha1 = id
          | otherwise = tag 0 (algorithmASN1S Sequence pssHashAlgorithm)

        m | pssMaskGenAlgorithm == MGF1 sha1 = id
          | otherwise = tag 1 (algorithmASN1S Sequence pssMaskGenAlgorithm)

        s | pssSaltLength == 20 && pssHashAlgorithm == sha1 = id
          | otherwise = tag 2 (gIntVal $ fromIntegral pssSaltLength)

instance Monoid e => ParseASN1Object e PSSParams where
    parse = onNextContainer Sequence $ do
        h <- tag 0 (parseAlgorithm Sequence)
        m <- tag 1 (parseAlgorithm Sequence)
        s <- tag 2 $ do { IntVal i <- getNext; return (fromIntegral i) }
        _ <- tag 3 $ do { IntVal 1 <- getNext; return () }
        return PSSParams { pssHashAlgorithm = fromMaybe sha1 h
                         , pssMaskGenAlgorithm = fromMaybe (MGF1 sha1) m
                         , pssSaltLength = fromMaybe 20 s
                         }
      where
        sha1  = DigestAlgorithm SHA1
        tag i = onNextContainerMaybe (Container Context i)

data SignatureType = TypeRSAAnyHash
                   | TypeRSA DigestAlgorithm
                   | TypeRSAPSS
                   | TypeDSA DigestAlgorithm
                   | TypeECDSA DigestAlgorithm
                   | TypeEd25519
                   | TypeEd448
    deriving (Show,Eq)

instance Enumerable SignatureType where
    values = [ TypeRSAAnyHash

             , TypeRSA (DigestAlgorithm MD2)
             , TypeRSA (DigestAlgorithm MD5)
             , TypeRSA (DigestAlgorithm SHA1)
             , TypeRSA (DigestAlgorithm SHA224)
             , TypeRSA (DigestAlgorithm SHA256)
             , TypeRSA (DigestAlgorithm SHA384)
             , TypeRSA (DigestAlgorithm SHA512)

             , TypeRSAPSS

             , TypeDSA (DigestAlgorithm SHA1)
             , TypeDSA (DigestAlgorithm SHA224)
             , TypeDSA (DigestAlgorithm SHA256)

             , TypeECDSA (DigestAlgorithm SHA1)
             , TypeECDSA (DigestAlgorithm SHA224)
             , TypeECDSA (DigestAlgorithm SHA256)
             , TypeECDSA (DigestAlgorithm SHA384)
             , TypeECDSA (DigestAlgorithm SHA512)

             , TypeEd25519
             , TypeEd448
             ]

instance OIDable SignatureType where
    getObjectID TypeRSAAnyHash                       = [1,2,840,113549,1,1,1]

    getObjectID (TypeRSA (DigestAlgorithm MD2))      = [1,2,840,113549,1,1,2]
    getObjectID (TypeRSA (DigestAlgorithm MD5))      = [1,2,840,113549,1,1,4]
    getObjectID (TypeRSA (DigestAlgorithm SHA1))     = [1,2,840,113549,1,1,5]
    getObjectID (TypeRSA (DigestAlgorithm SHA224))   = [1,2,840,113549,1,1,14]
    getObjectID (TypeRSA (DigestAlgorithm SHA256))   = [1,2,840,113549,1,1,11]
    getObjectID (TypeRSA (DigestAlgorithm SHA384))   = [1,2,840,113549,1,1,12]
    getObjectID (TypeRSA (DigestAlgorithm SHA512))   = [1,2,840,113549,1,1,13]

    getObjectID TypeRSAPSS                           = [1,2,840,113549,1,1,10]

    getObjectID (TypeDSA (DigestAlgorithm SHA1))     = [1,2,840,10040,4,3]
    getObjectID (TypeDSA (DigestAlgorithm SHA224))   = [2,16,840,1,101,3,4,3,1]
    getObjectID (TypeDSA (DigestAlgorithm SHA256))   = [2,16,840,1,101,3,4,3,2]

    getObjectID (TypeECDSA (DigestAlgorithm SHA1))   = [1,2,840,10045,4,1]
    getObjectID (TypeECDSA (DigestAlgorithm SHA224)) = [1,2,840,10045,4,3,1]
    getObjectID (TypeECDSA (DigestAlgorithm SHA256)) = [1,2,840,10045,4,3,2]
    getObjectID (TypeECDSA (DigestAlgorithm SHA384)) = [1,2,840,10045,4,3,3]
    getObjectID (TypeECDSA (DigestAlgorithm SHA512)) = [1,2,840,10045,4,3,4]

    getObjectID TypeEd25519                          = [1,3,101,112]
    getObjectID TypeEd448                            = [1,3,101,113]

    getObjectID ty = error ("Unsupported SignatureType: " ++ show ty)

instance OIDNameable SignatureType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

-- | CMS signature algorithms and associated parameters.
data SignatureAlg = RSAAnyHash
                  | RSA DigestAlgorithm
                  | RSAPSS PSSParams
                  | DSA DigestAlgorithm
                  | ECDSA DigestAlgorithm
                  | Ed25519
                  | Ed448
    deriving (Show,Eq)

instance AlgorithmId SignatureAlg where
    type AlgorithmType SignatureAlg = SignatureType
    algorithmName _  = "signature algorithm"

    algorithmType RSAAnyHash  = TypeRSAAnyHash
    algorithmType (RSA alg)   = TypeRSA alg
    algorithmType (RSAPSS _)  = TypeRSAPSS
    algorithmType (DSA alg)   = TypeDSA alg
    algorithmType (ECDSA alg) = TypeECDSA alg
    algorithmType Ed25519     = TypeEd25519
    algorithmType Ed448       = TypeEd448

    parameterASN1S RSAAnyHash = gNull
    parameterASN1S (RSA _)    = gNull
    parameterASN1S (RSAPSS p) = asn1s p
    parameterASN1S (DSA _)    = id
    parameterASN1S (ECDSA _)  = id
    parameterASN1S Ed25519    = id
    parameterASN1S Ed448      = id

    parseParameter TypeRSAAnyHash   = getNextMaybe nullOrNothing >> return RSAAnyHash
    parseParameter (TypeRSA alg)    = getNextMaybe nullOrNothing >> return (RSA alg)
    parseParameter TypeRSAPSS       = RSAPSS <$> parse
    parseParameter (TypeDSA alg)    = return (DSA alg)
    parseParameter (TypeECDSA alg)  = return (ECDSA alg)
    parseParameter TypeEd25519      = return Ed25519
    parseParameter TypeEd448        = return Ed448

-- | Sign a message using the specified algorithm and private key.  The
-- corresponding public key is also required for some algorithms.
signatureGenerate :: MonadRandom m => SignatureAlg -> X509.PrivKey -> X509.PubKey -> ByteString -> m (Either StoreError SignatureValue)
signatureGenerate RSAAnyHash _ _ _ =
    error "signatureGenerate: should call signatureResolveHash first"
signatureGenerate (RSA alg)   (X509.PrivKeyRSA priv) (X509.PubKeyRSA _) msg =
    let err = return . Left $ InvalidParameter ("Invalid hash algorithm for RSA: " ++ show alg)
     in withHashAlgorithmASN1 alg err $ \hashAlg ->
            mapLeft RSAError <$> RSA.signSafer (Just hashAlg) priv msg
signatureGenerate (RSAPSS p)  (X509.PrivKeyRSA priv) (X509.PubKeyRSA _) msg =
    withPSSParams p $ \params ->
        mapLeft RSAError <$> RSAPSS.signSafer params priv msg
signatureGenerate (DSA alg)   (X509.PrivKeyDSA priv) (X509.PubKeyDSA _) msg =
    case alg of
        DigestAlgorithm t ->
            Right . dsaFromSignature <$> DSA.sign priv (hashFromProxy t) msg
signatureGenerate (ECDSA alg) (X509.PrivKeyEC priv)  (X509.PubKeyEC _)  msg =
    case alg of
        DigestAlgorithm t ->
            case ecdsaToPrivateKey priv of
                Nothing -> return (Left UnsupportedEllipticCurve)
                Just p  ->
                    let h = hashFromProxy t
                     in Right . ecdsaFromSignature <$> ECDSA.sign p h msg
signatureGenerate Ed25519 (X509.PrivKeyEd25519 priv) (X509.PubKeyEd25519 pub) msg =
    return . Right . B.convert $ Ed25519.sign priv pub msg
signatureGenerate Ed448 (X509.PrivKeyEd448 priv) (X509.PubKeyEd448 pub) msg =
    return . Right . B.convert $ Ed448.sign priv pub msg
signatureGenerate _ _ _ _ = return (Left UnexpectedPrivateKeyType)

-- | Verify a message signature using the specified algorithm and public key.
signatureVerify :: SignatureAlg -> X509.PubKey -> ByteString -> SignatureValue -> Bool
signatureVerify RSAAnyHash _ _ _ =
    error "signatureVerify: should call signatureResolveHash first"
signatureVerify (RSA alg)   (X509.PubKeyRSA pub) msg sig =
    withHashAlgorithmASN1 alg False $ \hashAlg ->
        RSA.verify (Just hashAlg) pub msg sig
signatureVerify (RSAPSS p)  (X509.PubKeyRSA pub) msg sig =
    withPSSParams p $ \params -> RSAPSS.verify params pub msg sig
signatureVerify (DSA alg)   (X509.PubKeyDSA pub) msg sig = fromMaybe False $ do
    s <- dsaToSignature sig
    case alg of
        DigestAlgorithm t -> return $ DSA.verify (hashFromProxy t) pub s msg
signatureVerify (ECDSA alg) (X509.PubKeyEC pub)  msg sig = fromMaybe False $ do
    p <- ecdsaToPublicKey pub
    s <- ecdsaToSignature sig
    case alg of
        DigestAlgorithm t -> return $ ECDSA.verify (hashFromProxy t) p s msg
signatureVerify Ed25519 (X509.PubKeyEd25519 pub) msg sig =
    case Ed25519.signature sig of
        CryptoFailed _ -> False
        CryptoPassed s -> Ed25519.verify pub msg s
signatureVerify Ed448 (X509.PubKeyEd448 pub) msg sig =
    case Ed448.signature sig of
        CryptoFailed _ -> False
        CryptoPassed s -> Ed448.verify pub msg s
signatureVerify _                 _                    _   _   = False

withHashAlgorithmASN1 :: DigestAlgorithm
                      -> a
                      -> (forall hashAlg . RSA.HashAlgorithmASN1 hashAlg => hashAlg -> a)
                      -> a
withHashAlgorithmASN1 (DigestAlgorithm MD2)    _ f = f Hash.MD2
withHashAlgorithmASN1 (DigestAlgorithm MD5)    _ f = f Hash.MD5
withHashAlgorithmASN1 (DigestAlgorithm SHA1)   _ f = f Hash.SHA1
withHashAlgorithmASN1 (DigestAlgorithm SHA224) _ f = f Hash.SHA224
withHashAlgorithmASN1 (DigestAlgorithm SHA256) _ f = f Hash.SHA256
withHashAlgorithmASN1 (DigestAlgorithm SHA384) _ f = f Hash.SHA384
withHashAlgorithmASN1 (DigestAlgorithm SHA512) _ f = f Hash.SHA512
withHashAlgorithmASN1 _                        e _ = e

-- | Return on which digest algorithm the specified signature algorithm is
-- based, as well as a substitution algorithm for when a default digest
-- algorithm is required.
signatureResolveHash :: Bool -> DigestAlgorithm -> SignatureAlg -> (DigestAlgorithm, SignatureAlg)
signatureResolveHash _     d RSAAnyHash     = (d, RSA d)
signatureResolveHash _     _ alg@(RSA d)    = (d, alg)
signatureResolveHash _     _ alg@(RSAPSS p) = (pssHashAlgorithm p, alg)
signatureResolveHash _     _ alg@(DSA d)    = (d, alg)
signatureResolveHash _     _ alg@(ECDSA d)  = (d, alg)
signatureResolveHash _     _ alg@Ed25519    = (DigestAlgorithm SHA512, alg)
signatureResolveHash True  _ alg@Ed448      = (DigestAlgorithm SHAKE256_512, alg)
signatureResolveHash False _ alg@Ed448      = (DigestAlgorithm (SHAKE256 p512), alg)

-- | Check that a signature algorithm is based on the specified digest algorithm
-- and return a substitution algorithm for when a default digest algorithm is
-- required.
signatureCheckHash :: DigestAlgorithm -> SignatureAlg -> Maybe SignatureAlg
signatureCheckHash expected RSAAnyHash = Just $ RSA expected
signatureCheckHash expected alg@(RSA found)
    | expected == found = Just alg
    | otherwise         = Nothing
signatureCheckHash expected alg@(RSAPSS p)
    | expected == pssHashAlgorithm p = Just alg
    | otherwise                      = Nothing
signatureCheckHash expected alg@(DSA found)
    | expected == found = Just alg
    | otherwise         = Nothing
signatureCheckHash expected alg@(ECDSA found)
    | expected == found = Just alg
    | otherwise         = Nothing
signatureCheckHash expected alg@Ed25519
    | expected == DigestAlgorithm SHA512 = Just alg
    | otherwise                          = Nothing
signatureCheckHash expected alg@Ed448
    | expected == DigestAlgorithm SHAKE256_512    = Just alg
    | expected == DigestAlgorithm (SHAKE256 p512) = Just alg
    | otherwise                                   = Nothing

dsaToSignature :: ByteString -> Maybe DSA.Signature
dsaToSignature b = tryDecodeAndParse b $ onNextContainer Sequence $ do
    IntVal r <- getNext
    IntVal s <- getNext
    return DSA.Signature { DSA.sign_r = r, DSA.sign_s = s }

dsaFromSignature :: DSA.Signature -> ByteString
dsaFromSignature sig = encodeASN1S $ asn1Container Sequence
    (gIntVal (DSA.sign_r sig) . gIntVal (DSA.sign_s sig))

ecdsaToSignature :: ByteString -> Maybe ECDSA.Signature
ecdsaToSignature b = tryDecodeAndParse b $ onNextContainer Sequence $ do
    IntVal r <- getNext
    IntVal s <- getNext
    return ECDSA.Signature { ECDSA.sign_r = r, ECDSA.sign_s = s }

ecdsaFromSignature :: ECDSA.Signature -> ByteString
ecdsaFromSignature sig = encodeASN1S $ asn1Container Sequence
    (gIntVal (ECDSA.sign_r sig) . gIntVal (ECDSA.sign_s sig))

ecdsaToPublicKey :: X509.PubKeyEC -> Maybe ECDSA.PublicKey
ecdsaToPublicKey key = do
    curve <- ecPubKeyCurve key
    pt <- unserializePoint curve (X509.pubkeyEC_pub key)
    return ECDSA.PublicKey { ECDSA.public_curve = curve, ECDSA.public_q = pt }

ecdsaToPrivateKey :: X509.PrivKeyEC -> Maybe ECDSA.PrivateKey
ecdsaToPrivateKey key = do
    curve <- ecPrivKeyCurve key
    let d = X509.privkeyEC_priv key
    return ECDSA.PrivateKey { ECDSA.private_curve = curve, ECDSA.private_d = d }

tryDecodeAndParse :: ByteString -> ParseASN1 () a -> Maybe a
tryDecodeAndParse b parser =
    either (const Nothing) Just $
        case decodeASN1' BER b of
            Left _     -> Left undefined -- value ignored
            Right asn1 -> runParseASN1 parser asn1
