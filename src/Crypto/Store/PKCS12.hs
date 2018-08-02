-- |
-- Module      : Crypto.Store.PKCS12
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Personal Information Exchange Syntax, aka PKCS #12.
--
-- Only password integrity mode and password privacy modes are supported.
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
module Crypto.Store.PKCS12
    ( IntegrityParams
    , readP12File
    , readP12FileFromMemory
    , writeP12File
    , writeP12FileToMemory
    , writeUnprotectedP12File
    , writeUnprotectedP12FileToMemory
    -- * PKCS #12 privacy
    , PKCS12
    , unPKCS12
    , unPKCS12'
    , unencrypted
    , encrypted
    -- * PKCS #12 contents and bags
    , SafeContents(..)
    , SafeBag
    , Bag(..)
    , SafeInfo(..)
    , CertInfo(..)
    , CRLInfo(..)
    , Attribute(..)
    , getSafeKeys
    , getSafeKeys'
    , getSafeX509Certs
    , getSafeX509CRLs
    -- * Password-based protection
    , Password
    , OptProtected(..)
    , recover
    , recoverA
    ) where

import Control.Monad

import           Data.ASN1.Types
import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import qualified Data.ByteArray as B
import qualified Data.ByteString as BS
import           Data.Maybe (fromMaybe)
import           Data.Semigroup
import qualified Data.X509 as X509

import Crypto.Cipher.Types

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Encrypted
import Crypto.Store.CMS.Util
import Crypto.Store.PKCS5
import Crypto.Store.PKCS5.PBES1
import Crypto.Store.PKCS8


-- Decoding and parsing

-- | Read a PKCS #12 file from disk.
readP12File :: FilePath -> IO (Either String (OptProtected PKCS12))
readP12File path = readP12FileFromMemory <$> BS.readFile path

-- | Read a PKCS #12 file from a bytearray in BER format.
readP12FileFromMemory :: BS.ByteString -> Either String (OptProtected PKCS12)
readP12FileFromMemory ber = decode ber >>= integrity
  where
    integrity PFX{..} =
        case macData of
            Nothing -> Unprotected <$> decode authSafeData
            Just md -> return $ Protected (verify md authSafeData)

    verify MacData{..} content pwdUTF8 =
        case digAlg of
            DigestType d ->
                let fn key macAlg bs
                        | macValue == mac macAlg key bs = decode bs
                        | otherwise = Left "Bac content MAC, invalid password?"
                 in pkcs12mac Left fn d macParams content pwdUTF8


-- Generating and encoding

-- | Parameters used for password integrity mode.
type IntegrityParams = (DigestType, PBEParameter)

-- | Write a PKCS #12 file to disk.
writeP12File :: FilePath
             -> IntegrityParams -> Password
             -> PKCS12
             -> IO (Either String ())
writeP12File path intp pw aSafe =
    case writeP12FileToMemory intp pw aSafe of
        Left e   -> return (Left e)
        Right bs -> Right <$> BS.writeFile path bs

-- | Write a PKCS #12 file to a bytearray in DER format.
writeP12FileToMemory :: IntegrityParams -> Password
                     -> PKCS12
                     -> Either String BS.ByteString
writeP12FileToMemory (alg@(DigestType hashAlg), pbeParam) pwdUTF8 aSafe =
    encode <$> protect
  where
    content   = encodeASN1Object aSafe
    encode md = encodeASN1Object PFX { authSafeData = content, macData = Just md }

    protect = pkcs12mac Left fn hashAlg pbeParam content pwdUTF8
    fn key macAlg bs = Right MacData { digAlg    = alg
                                     , macValue  = mac macAlg key bs
                                     , macParams = pbeParam
                                     }

-- | Write a PKCS #12 file without integrity protection to disk.
writeUnprotectedP12File :: FilePath -> PKCS12 -> IO ()
writeUnprotectedP12File path = BS.writeFile path . writeUnprotectedP12FileToMemory

-- | Write a PKCS #12 file without integrity protection to a bytearray in DER
-- format.
writeUnprotectedP12FileToMemory :: PKCS12 -> BS.ByteString
writeUnprotectedP12FileToMemory aSafe = encodeASN1Object pfx
  where
    content = encodeASN1Object aSafe
    pfx     = PFX { authSafeData = content, macData = Nothing }


-- PFX and MacData

data PFX = PFX
    { authSafeData :: BS.ByteString
    , macData :: Maybe MacData
    }
    deriving (Show,Eq)

instance ProduceASN1Object ASN1P PFX where
    asn1s PFX{..} =
        asn1Container Sequence (v . a . m)
      where
        v = gIntVal 3
        a = asn1s (DataCI authSafeData)
        m = optASN1S macData asn1s

instance ParseASN1Object [ASN1Event] PFX where
    parse = onNextContainer Sequence $ do
        IntVal v <- getNext
        when (v /= 3) $
            throwParseError ("PFX: parsed invalid version: " ++ show v)
        ci <- parse
        d <- case ci of
                 DataCI bs      -> return bs
                 SignedDataCI _ -> throwParseError "PFX: public-key integrity mode is not supported"
                 _              -> throwParseError $ "PFX: invalid content type: " ++ show (getContentType ci)
        b <- hasNext
        m <- if b then Just <$> parse else pure Nothing
        return PFX { authSafeData = d, macData = m }

data MacData = MacData
    { digAlg :: DigestType
    , macValue :: MessageAuthenticationCode
    , macParams :: PBEParameter
    }
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e MacData where
    asn1s MacData{..} =
        asn1Container Sequence (m . s . i)
      where
        m = asn1Container Sequence (a . v)
        a = algorithmASN1S Sequence digAlg
        v = gOctetString (B.convert macValue)
        s = gOctetString (pbeSalt macParams)
        i = gIntVal (fromIntegral $ pbeIterationCount macParams)

instance Monoid e => ParseASN1Object e MacData where
    parse = onNextContainer Sequence $ do
        (a, v) <- onNextContainer Sequence $ do
            a <- parseAlgorithm Sequence
            OctetString v <- getNext
            return (a, v)
        OctetString s <- getNext
        b <- hasNext
        IntVal i <- if b then getNext else pure (IntVal 1)
        return MacData { digAlg = a
                       , macValue = AuthTag (B.convert v)
                       , macParams = PBEParameter s (fromIntegral i)
                       }


-- AuthenticatedSafe

-- | PKCS #12 privacy wrapper, adding optional encryption to 'SafeContents'.
-- ASN.1 equivalent is @AuthenticatedSafe@.
--
-- The monoid interface allows to combine multiple pieces encrypted separately
-- but they should all derive from the same password to be readable by
-- 'unPKCS12' and most software.
newtype PKCS12 = PKCS12 [ASElement]
    deriving (Show,Eq)

instance Semigroup PKCS12 where
    PKCS12 a <> PKCS12 b = PKCS12 (a ++ b)

instance ProduceASN1Object ASN1P PKCS12 where
    asn1s (PKCS12 elems) = asn1Container Sequence (asn1s elems)

instance ParseASN1Object [ASN1Event] PKCS12 where
    parse = PKCS12 <$> onNextContainer Sequence parse

-- | Read the contents of a PKCS #12.  The same privacy password will be used
-- for all content elements.
unPKCS12 :: PKCS12 -> OptProtected [SafeContents]
unPKCS12 = applySamePassword . unPKCS12'

-- | Read the contents of a PKCS #12.
unPKCS12' :: PKCS12 -> [OptProtected SafeContents]
unPKCS12' (PKCS12 elems) = map f elems
  where f (Unencrypted sc) = Unprotected sc
        f (Encrypted e)    = Protected (decrypt e >=> decode)

-- | Build a PKCS #12 without encryption.  Usage scenario is when private keys
-- are already encrypted with 'PKCS8ShroudedKeyBag'.
unencrypted :: SafeContents -> PKCS12
unencrypted = PKCS12 . (:[]) . Unencrypted

-- | Build a PKCS #12 encrypted with the specified scheme and password.
encrypted :: EncryptionScheme -> Password -> SafeContents -> Either String PKCS12
encrypted alg pwd sc = PKCS12 . (:[]) . Encrypted <$> encrypt alg pwd bs
  where bs = encodeASN1Object sc

data ASElement = Unencrypted SafeContents
               | Encrypted PKCS5
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e ASElement where
    asn1s (Unencrypted sc) = asn1Container Sequence (oid . cont)
      where
        oid = gOID (getObjectID DataType)
        cont = asn1Container (Container Context 0) (gOctetString bs)
        bs = encodeASN1Object sc

    asn1s (Encrypted PKCS5{..}) = asn1Container Sequence (oid . cont)
      where
        oid = gOID (getObjectID EncryptedDataType)
        cont = asn1Container (Container Context 0) inner
        inner = asn1Container Sequence (gIntVal 0 . eci)
        eci = encryptedContentInfoASN1S
                  (DataType, encryptionAlgorithm, encryptedData)

instance Monoid e => ParseASN1Object e ASElement where
    parse = onNextContainer Sequence $ do
        OID oid <- getNext
        withObjectID "content type" oid $ \ct ->
            onNextContainer (Container Context 0) (parseInner ct)
      where
        parseInner DataType          = Unencrypted <$> parseUnencrypted
        parseInner EncryptedDataType = Encrypted <$> parseEncrypted
        parseInner EnvelopedDataType = throwParseError "PKCS12: public-key privacy mode is not supported"
        parseInner ct                = throwParseError $ "PKCS12: invalid content type: " ++ show ct

        parseUnencrypted = parseOctetStringObject "PKCS12"
        parseEncrypted = onNextContainer Sequence $ do
            IntVal 0 <- getNext
            (DataType, eScheme, ed) <- parseEncryptedContentInfo
            return PKCS5 { encryptionAlgorithm = eScheme, encryptedData = ed }


-- Bags

-- | Polymorphic PKCS #12 bag parameterized by the payload data type.
data Bag info = Bag
    { bagInfo :: info              -- ^ bag payload
    , bagAttributes :: [Attribute] -- ^ attributes providing additional information
    }
    deriving (Show,Eq)

class BagInfo info where
    type BagType info
    bagName  :: info -> String
    bagType  :: info -> BagType info
    valueASN1S :: ASN1Elem e => info -> ASN1Stream e
    parseValue :: Monoid e => BagType info -> ParseASN1 e info

instance (ASN1Elem e, BagInfo info, OIDable (BagType info)) => ProduceASN1Object e (Bag info) where
    asn1s Bag{..} = asn1Container Sequence (oid . val . att)
      where
        typ = bagType bagInfo
        oid = gOID (getObjectID typ)
        val = asn1Container (Container Context 0) (valueASN1S bagInfo)

        att | null bagAttributes = id
            | otherwise          = asn1Container Set (asn1s bagAttributes)

instance (Monoid e, BagInfo info, OIDNameable (BagType info)) => ParseASN1Object e (Bag info) where
    parse = onNextContainer Sequence $ do
        OID oid <- getNext
        val <- withObjectID (getName undefined) oid $
                   onNextContainer (Container Context 0) . parseValue
        att <- fromMaybe [] <$> onNextContainerMaybe Set parse
        return Bag { bagInfo = val, bagAttributes = att }
      where
        getName :: info -> String
        getName = bagName

data CertType = TypeCertX509 deriving (Show,Eq)

instance Enumerable CertType where
    values = [ TypeCertX509 ]

instance OIDable CertType where
    getObjectID TypeCertX509 = [1,2,840,113549,1,9,22,1]

instance OIDNameable CertType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

-- | Certificate bags.  Only X.509 certificates are supported.
newtype CertInfo = CertX509 X509.SignedCertificate deriving (Show,Eq)

instance BagInfo CertInfo where
    type BagType CertInfo = CertType
    bagName _ = "CertBag"
    bagType (CertX509 _) = TypeCertX509
    valueASN1S (CertX509 c) = gOctetString (encodeASN1Object c)
    parseValue TypeCertX509 = CertX509 <$> parseOctetStringObject "CertBag"

data CRLType = TypeCRLX509 deriving (Show,Eq)

instance Enumerable CRLType where
    values = [ TypeCRLX509 ]

instance OIDable CRLType where
    getObjectID TypeCRLX509 = [1,2,840,113549,1,9,23,1]

instance OIDNameable CRLType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

-- | CRL bags.  Only X.509 CRLs are supported.
newtype CRLInfo = CRLX509 X509.SignedCRL deriving (Show,Eq)

instance BagInfo CRLInfo where
    type BagType CRLInfo = CRLType
    bagName _ = "CRLBag"
    bagType (CRLX509 _) = TypeCRLX509
    valueASN1S (CRLX509 c) = gOctetString (encodeASN1Object c)
    parseValue TypeCRLX509 = CRLX509 <$> parseOctetStringObject "CRLBag"

data SafeType = TypeKey
              | TypePKCS8ShroudedKey
              | TypeCert
              | TypeCRL
              | TypeSecret
              | TypeSafeContents
    deriving (Show,Eq)

instance Enumerable SafeType where
    values = [ TypeKey
             , TypePKCS8ShroudedKey
             , TypeCert
             , TypeCRL
             , TypeSecret
             , TypeSafeContents
             ]

instance OIDable SafeType where
    getObjectID TypeKey              = [1,2,840,113549,1,12,10,1,1]
    getObjectID TypePKCS8ShroudedKey = [1,2,840,113549,1,12,10,1,2]
    getObjectID TypeCert             = [1,2,840,113549,1,12,10,1,3]
    getObjectID TypeCRL              = [1,2,840,113549,1,12,10,1,4]
    getObjectID TypeSecret           = [1,2,840,113549,1,12,10,1,5]
    getObjectID TypeSafeContents     = [1,2,840,113549,1,12,10,1,6]

instance OIDNameable SafeType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

-- | Main bag payload in PKCS #12 contents.
data SafeInfo = KeyBag (FormattedKey X509.PrivKey) -- ^ unencrypted private key
              | PKCS8ShroudedKeyBag PKCS5          -- ^ encrypted private key
              | CertBag (Bag CertInfo)             -- ^ certificate
              | CRLBag (Bag CRLInfo)               -- ^ CRL
              | SecretBag [ASN1]                   -- ^ arbitrary secret
              | SafeContentsBag SafeContents       -- ^ safe contents embeded recursively
    deriving (Show,Eq)

instance BagInfo SafeInfo where
    type BagType SafeInfo = SafeType
    bagName _ = "SafeBag"

    bagType (KeyBag _)              = TypeKey
    bagType (PKCS8ShroudedKeyBag _) = TypePKCS8ShroudedKey
    bagType (CertBag _)             = TypeCert
    bagType (CRLBag _)              = TypeCRL
    bagType (SecretBag _)           = TypeSecret
    bagType (SafeContentsBag _)     = TypeSafeContents

    valueASN1S (KeyBag k)              = asn1s k
    valueASN1S (PKCS8ShroudedKeyBag k) = asn1s k
    valueASN1S (CertBag c)             = asn1s c
    valueASN1S (CRLBag c)              = asn1s c
    valueASN1S (SecretBag s)           = gMany s
    valueASN1S (SafeContentsBag sc)    = asn1s sc

    parseValue TypeKey              = KeyBag <$> parse
    parseValue TypePKCS8ShroudedKey = PKCS8ShroudedKeyBag <$> parse
    parseValue TypeCert             = CertBag <$> parse
    parseValue TypeCRL              = CRLBag <$> parse
    parseValue TypeSecret           = SecretBag <$> getMany getNext
    parseValue TypeSafeContents     = SafeContentsBag <$> parse

-- | Main bag type in a PKCS #12.
type SafeBag = Bag SafeInfo

-- | Content objects stored in a PKCS #12.
newtype SafeContents = SafeContents { unSafeContents :: [SafeBag] }
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e SafeContents where
    asn1s (SafeContents s) = asn1Container Sequence (asn1s s)

instance Monoid e => ParseASN1Object e SafeContents where
    parse = SafeContents <$> onNextContainer Sequence parse

-- | Return all private keys contained in the safe contents.  All shrouded
-- private keys must derive from the same password.
getSafeKeys :: SafeContents -> OptProtected [X509.PrivKey]
getSafeKeys = applySamePassword . getSafeKeys'

-- | Return all private keys contained in the safe contents.
getSafeKeys' :: SafeContents -> [OptProtected X509.PrivKey]
getSafeKeys' (SafeContents scs) = loop scs
  where
    loop []           = []
    loop (bag : bags) =
        case bagInfo bag of
            KeyBag (FormattedKey _ k) -> Unprotected k : loop bags
            PKCS8ShroudedKeyBag k     -> Protected (unshroud k) : loop bags
            SafeContentsBag inner     -> getSafeKeys' inner ++ loop bags
            _                         -> loop bags

    unshroud shrouded pwd = do
        bs <- decrypt shrouded pwd
        FormattedKey _ k <- decode bs
        return k

-- | Return all X.509 certificates contained in the safe contents.
getSafeX509Certs :: SafeContents -> [X509.SignedCertificate]
getSafeX509Certs (SafeContents scs) = loop scs
  where
    loop []           = []
    loop (bag : bags) =
        case bagInfo bag of
            CertBag (Bag (CertX509 c) _) -> c : loop bags
            SafeContentsBag inner        -> getSafeX509Certs inner ++ loop bags
            _                            -> loop bags

-- | Return all X.509 CRLs contained in the safe contents.
getSafeX509CRLs :: SafeContents -> [X509.SignedCRL]
getSafeX509CRLs (SafeContents scs) = loop scs
  where
    loop []           = []
    loop (bag : bags) =
        case bagInfo bag of
            CRLBag (Bag (CRLX509 c) _) -> c : loop bags
            SafeContentsBag inner      -> getSafeX509CRLs inner ++ loop bags
            _                          -> loop bags


-- Utilities

applySamePassword :: [OptProtected a] -> OptProtected [a]
applySamePassword [] = Unprotected []
applySamePassword (Unprotected e : xs) =
    case applySamePassword xs of
        Unprotected es -> Unprotected (e : es)
        Protected f    -> Protected (fmap (e :) . f)
applySamePassword (Protected f : xs) =
    case applySamePassword xs of
        Unprotected es -> Protected (fmap (: es) . f)
        Protected g    -> Protected (addTail g)
  where addTail g pwd = do
            e <- f pwd
            es <- g pwd
            return (e : es)

decode :: ParseASN1Object [ASN1Event] obj => BS.ByteString -> Either String obj
decode bs =
    case decodeASN1Repr' BER bs of
        Left e     -> Left ("PKCS12: unable to decode: " ++ show e)
        Right asn1 ->
            case fromASN1Repr asn1 of
                Right (obj, []) -> Right obj
                Right _         -> Left "PKCS12: incomplete parse"
                Left e          -> Left e

parseOctetStringObject :: (Monoid e, ParseASN1Object [ASN1Event] obj)
                       => String -> ParseASN1 e obj
parseOctetStringObject name = do
    OctetString bs <- getNext
    case decode bs of
        Left e  -> throwParseError (name ++ ": " ++ e)
        Right c -> return c
