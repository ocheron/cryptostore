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
    , getAllSafeKeys
    , getSafeX509Certs
    , getAllSafeX509Certs
    , getSafeX509CRLs
    , getAllSafeX509CRLs
    -- * PKCS #12 attributes
    , findAttribute
    , setAttribute
    , filterAttributes
    , getFriendlyName
    , setFriendlyName
    , getLocalKeyId
    , setLocalKeyId
    -- * Credentials
    , fromCredential
    , fromNamedCredential
    , toCredential
    , toNamedCredential
    -- * Password-based protection
    , ProtectionPassword
    , emptyNotTerminated
    , fromProtectionPassword
    , toProtectionPassword
    , OptProtected(..)
    , recover
    , recoverA
    ) where

import Control.Monad

import           Data.ASN1.Types
import qualified Data.ByteArray as B
import qualified Data.ByteString as BS
import           Data.List (partition)
import           Data.Maybe (fromMaybe, mapMaybe)
import           Data.Semigroup
import qualified Data.X509 as X509
import qualified Data.X509.Validation as X509

import Crypto.Cipher.Types

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Attribute
import Crypto.Store.CMS.Encrypted
import Crypto.Store.CMS.Util
import Crypto.Store.Error
import Crypto.Store.PKCS5
import Crypto.Store.PKCS5.PBES1
import Crypto.Store.PKCS8


-- Decoding and parsing

-- | Read a PKCS #12 file from disk.
readP12File :: FilePath -> IO (Either StoreError (OptProtected PKCS12))
readP12File path = readP12FileFromMemory <$> BS.readFile path

-- | Read a PKCS #12 file from a bytearray in BER format.
readP12FileFromMemory :: BS.ByteString -> Either StoreError (OptProtected PKCS12)
readP12FileFromMemory ber = decode ber >>= integrity
  where
    integrity PFX{..} =
        case macData of
            Nothing -> Unprotected <$> decode authSafeData
            Just md -> return $ Protected (verify md authSafeData)

    verify MacData{..} content pwdUTF8 =
        case digAlg of
            DigestAlgorithm d ->
                let fn key macAlg bs
                        | not (securityAcceptable macAlg) =
                            Left (InvalidParameter "Integrity MAC too weak")
                        | macValue == mac macAlg key bs = decode bs
                        | otherwise = Left BadContentMAC
                 in pkcs12mac Left fn d macParams content pwdUTF8


-- Generating and encoding

-- | Parameters used for password integrity mode.
type IntegrityParams = (DigestAlgorithm, PBEParameter)

-- | Write a PKCS #12 file to disk.
writeP12File :: FilePath
             -> IntegrityParams -> ProtectionPassword
             -> PKCS12
             -> IO (Either StoreError ())
writeP12File path intp pw aSafe =
    case writeP12FileToMemory intp pw aSafe of
        Left e   -> return (Left e)
        Right bs -> Right <$> BS.writeFile path bs

-- | Write a PKCS #12 file to a bytearray in DER format.
writeP12FileToMemory :: IntegrityParams -> ProtectionPassword
                     -> PKCS12
                     -> Either StoreError BS.ByteString
writeP12FileToMemory (alg@(DigestAlgorithm hashAlg), pbeParam) pwdUTF8 aSafe =
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
    { digAlg :: DigestAlgorithm
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
-- The semigroup interface allows to combine multiple pieces encrypted
-- separately but they should all derive from the same password to be readable
-- by 'unPKCS12' and most other software.
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
--
-- This convenience function returns a 'Protected' value as soon as one element
-- at least is encrypted.  This does not mean all elements were actually
-- protected in the input.  If detailed view is required then function
-- 'unPKCS12'' is also available.
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
encrypted :: EncryptionScheme -> ProtectionPassword -> SafeContents -> Either StoreError PKCS12
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
                  (DataType, encryptionAlgorithm, Attached encryptedData)

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
            (DataType, eScheme, Attached ed) <- parseEncryptedContentInfo
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

filterBags :: ([Attribute] -> Bool) -> SafeContents -> SafeContents
filterBags p (SafeContents scs) = SafeContents (mapMaybe f scs)
  where
    f (Bag (SafeContentsBag inner) attrs) =
        Just (Bag (SafeContentsBag $ filterBags p inner) attrs)
    f bag | p (bagAttributes bag)         = Just bag
          | otherwise                     = Nothing

filterByFriendlyName :: String -> SafeContents -> SafeContents
filterByFriendlyName name = filterBags ((== Just name) . getFriendlyName)

filterByLocalKeyId :: BS.ByteString -> SafeContents -> SafeContents
filterByLocalKeyId d = filterBags ((== Just d) . getLocalKeyId)

getSafeKeysId :: SafeContents -> [OptProtected (Id X509.PrivKey)]
getSafeKeysId (SafeContents scs) = loop scs
  where
    loop []           = []
    loop (bag : bags) =
        case bagInfo bag of
            KeyBag (FormattedKey _ k) -> Unprotected (mkId k bag) : loop bags
            PKCS8ShroudedKeyBag k     -> Protected (unshroud k bag) : loop bags
            SafeContentsBag inner     -> getSafeKeysId inner ++ loop bags
            _                         -> loop bags

    unshroud shrouded bag pwd = do
        bs <- decrypt shrouded pwd
        FormattedKey _ k <- decode bs
        return (mkId k bag)

-- | Return all private keys contained in the safe contents.
getSafeKeys :: SafeContents -> [OptProtected X509.PrivKey]
getSafeKeys = map (fmap unId) . getSafeKeysId

getAllSafeKeysId :: [SafeContents] -> OptProtected [Id X509.PrivKey]
getAllSafeKeysId = applySamePassword . concatMap getSafeKeysId

-- | Return all private keys contained in the safe content list.  All shrouded
-- private keys must derive from the same password.
--
-- This convenience function returns a 'Protected' value as soon as one key at
-- least is encrypted.  This does not mean all keys were actually protected in
-- the input.  If detailed view is required then function 'getSafeKeys' is
-- available.
getAllSafeKeys :: [SafeContents] -> OptProtected [X509.PrivKey]
getAllSafeKeys = applySamePassword . concatMap getSafeKeys

getSafeX509CertsId :: SafeContents -> [Id X509.SignedCertificate]
getSafeX509CertsId (SafeContents scs) = loop scs
  where
    loop []           = []
    loop (bag : bags) =
        case bagInfo bag of
            CertBag (Bag (CertX509 c) _) -> mkId c bag : loop bags
            SafeContentsBag inner        -> getSafeX509CertsId inner ++ loop bags
            _                            -> loop bags

-- | Return all X.509 certificates contained in the safe contents.
getSafeX509Certs :: SafeContents -> [X509.SignedCertificate]
getSafeX509Certs = map unId . getSafeX509CertsId

-- | Return all X.509 certificates contained in the safe content list.
getAllSafeX509Certs :: [SafeContents] -> [X509.SignedCertificate]
getAllSafeX509Certs = concatMap getSafeX509Certs

getSafeX509CRLsId :: SafeContents -> [Id X509.SignedCRL]
getSafeX509CRLsId (SafeContents scs) = loop scs
  where
    loop []           = []
    loop (bag : bags) =
        case bagInfo bag of
            CRLBag (Bag (CRLX509 c) _) -> mkId c bag : loop bags
            SafeContentsBag inner      -> getSafeX509CRLsId inner ++ loop bags
            _                          -> loop bags

-- | Return all X.509 CRLs contained in the safe contents.
getSafeX509CRLs :: SafeContents -> [X509.SignedCRL]
getSafeX509CRLs = map unId . getSafeX509CRLsId

-- | Return all X.509 CRLs contained in the safe content list.
getAllSafeX509CRLs :: [SafeContents] -> [X509.SignedCRL]
getAllSafeX509CRLs = concatMap getSafeX509CRLs


-- Conversion to/from credentials

getInnerCredential :: [SafeContents] -> SamePassword (Maybe (X509.CertificateChain, X509.PrivKey))
getInnerCredential l = SamePassword (fn <$> getAllSafeKeysId l)
  where
    certs     = getAllSafeX509Certs l
    fn idKeys = do
        iKey <- single idKeys
        let k = unId iKey
        case idKeyId iKey of
            Just d  -> do
                -- locate a single certificate with same ID as private key
                -- and follow the issuers to get all certificates in the chain
                let filtered = map (filterByLocalKeyId d) l
                leaf <- single (getAllSafeX509Certs filtered)
                pure (buildCertificateChain leaf certs, k)
            Nothing ->
                case idName iKey of
                    Just name -> do
                        -- same but using friendly name of private key
                        let filtered = map (filterByFriendlyName name) l
                        leaf <- single (getAllSafeX509Certs filtered)
                        pure (buildCertificateChain leaf certs, k)
                    Nothing   -> do
                        -- no identifier available, so we simply return all
                        -- certificates with input order
                        guard (not $ null certs)
                        pure (X509.CertificateChain certs, k)

-- | Extract the private key and certificate chain from a 'PKCS12' value.  A
-- credential is returned when the structure contains exactly one private key
-- and at least one X.509 certificate.
toCredential :: PKCS12 -> OptProtected (Maybe (X509.CertificateChain, X509.PrivKey))
toCredential p12 =
    unSamePassword (SamePassword (unPKCS12 p12) >>= getInnerCredential)

getInnerCredentialNamed :: String -> [SafeContents] -> SamePassword (Maybe (X509.CertificateChain, X509.PrivKey))
getInnerCredentialNamed name l = SamePassword (fn <$> getAllSafeKeys filtered)
  where
    certs    = getAllSafeX509Certs l
    filtered = map (filterByFriendlyName name) l
    fn keys  = do
        k <- single keys
        leaf <- single (getAllSafeX509Certs filtered)
        pure (buildCertificateChain leaf certs, k)

-- | Extract a private key and certificate chain with the specified friendly
-- name from a 'PKCS12' value.  A credential is returned when the structure
-- contains exactly one private key and one X.509 certificate with the name.
toNamedCredential :: String -> PKCS12 -> OptProtected (Maybe (X509.CertificateChain, X509.PrivKey))
toNamedCredential name p12 = unSamePassword $
    SamePassword (unPKCS12 p12) >>= getInnerCredentialNamed name

-- | Build a 'PKCS12' value containing a private key and certificate chain.
-- Distinct encryption is applied for both.  Encrypting the certificate chain is
-- optional.
--
-- Note: advice is to always generate fresh and independent 'EncryptionScheme'
-- values so that the salt is not reused twice in the encryption process.
fromCredential :: Maybe EncryptionScheme -- for certificates
               -> EncryptionScheme       -- for private key
               -> ProtectionPassword
               -> (X509.CertificateChain, X509.PrivKey)
               -> Either StoreError PKCS12
fromCredential = fromCredential' id

-- | Build a 'PKCS12' value containing a private key and certificate chain
-- identified with the specified friendly name.  Distinct encryption is applied
-- for private key and certificates.  Encrypting the certificate chain is
-- optional.
--
-- Note: advice is to always generate fresh and independent 'EncryptionScheme'
-- values so that the salt is not reused twice in the encryption process.
fromNamedCredential :: String
                    -> Maybe EncryptionScheme -- for certificates
                    -> EncryptionScheme       -- for private key
                    -> ProtectionPassword
                    -> (X509.CertificateChain, X509.PrivKey)
                    -> Either StoreError PKCS12
fromNamedCredential name = fromCredential' (setFriendlyName name)

fromCredential' :: ([Attribute] -> [Attribute])
                -> Maybe EncryptionScheme -- for certificates
                -> EncryptionScheme       -- for private key
                -> ProtectionPassword
                -> (X509.CertificateChain, X509.PrivKey)
                -> Either StoreError PKCS12
fromCredential' trans algChain algKey pwd (X509.CertificateChain certs, key)
    | null certs = Left (InvalidInput "Empty certificate chain")
    | otherwise  = (<>) <$> pkcs12Chain <*> pkcs12Key
  where
    pkcs12Key   = unencrypted <$> scKeyOrError
    pkcs12Chain =
        case algChain of
            Just alg -> encrypted alg pwd scChain
            Nothing  -> Right (unencrypted scChain)

    scChain       = SafeContents (zipWith toCertBag certAttrs certs)
    certAttrs     = attrs : repeat []
    toCertBag a c = Bag (CertBag (Bag (CertX509 c) [])) a

    scKeyOrError = wrap <$> encrypt algKey pwd encodedKey

    wrap shrouded = SafeContents [Bag (PKCS8ShroudedKeyBag shrouded) attrs]
    encodedKey    = encodeASN1Object (FormattedKey PKCS8Format key)

    X509.Fingerprint keyId = X509.getFingerprint (head certs) X509.HashSHA1
    attrs = trans (setLocalKeyId keyId [])

-- Standard attributes

friendlyName :: OID
friendlyName = [1,2,840,113549,1,9,20]

-- | Return the value of the @friendlyName@ attribute.
getFriendlyName :: [Attribute] -> Maybe String
getFriendlyName attrs = runParseAttribute friendlyName attrs $ do
    ASN1String str <- getNext
    case asn1CharacterToString str of
        Nothing -> throwParseError "Invalid friendlyName value"
        Just s  -> return s

-- | Add or replace the @friendlyName@ attribute in a list of attributes.
setFriendlyName :: String -> [Attribute] -> [Attribute]
setFriendlyName name = setAttributeASN1S friendlyName (gBMPString name)

localKeyId :: OID
localKeyId = [1,2,840,113549,1,9,21]

-- | Return the value of the @localKeyId@ attribute.
getLocalKeyId :: [Attribute] -> Maybe BS.ByteString
getLocalKeyId attrs = runParseAttribute localKeyId attrs $ do
    OctetString d <- getNext
    return d

-- | Add or replace the @localKeyId@ attribute in a list of attributes.
setLocalKeyId :: BS.ByteString -> [Attribute] -> [Attribute]
setLocalKeyId d = setAttributeASN1S localKeyId (gOctetString d)


-- Utilities

-- Internal wrapper of OptProtected providing Applicative and Monad instances.
--
-- This adds the following constraint: all values composed must derive from the
-- same encryption password.  Semantically, 'Protected' actually means
-- "requiring a password".  Otherwise composition of 'Protected' and
-- 'Unprotected' values is unsound.
newtype SamePassword a = SamePassword { unSamePassword :: OptProtected a }

instance Functor SamePassword where
    fmap f (SamePassword opt) = SamePassword (fmap f opt)

instance Applicative SamePassword where
    pure a = SamePassword (Unprotected a)

    SamePassword (Unprotected f) <*> SamePassword (Unprotected x) =
        SamePassword (Unprotected (f x))

    SamePassword (Unprotected f) <*> SamePassword (Protected x) =
        SamePassword $ Protected (fmap f . x)

    SamePassword (Protected f) <*> SamePassword (Unprotected x) =
        SamePassword $ Protected (fmap ($ x) . f)

    SamePassword (Protected f) <*> SamePassword (Protected x) =
        SamePassword $ Protected (\pwd -> f pwd <*> x pwd)

instance Monad SamePassword where
    return = pure

    SamePassword (Unprotected x)   >>= f = f x
    SamePassword (Protected inner) >>= f =
        SamePassword . Protected $ \pwd ->
            case inner pwd of
                Left err -> Left err
                Right x  -> recover pwd (unSamePassword $ f x)

applySamePassword :: [OptProtected a] -> OptProtected [a]
applySamePassword = unSamePassword . traverse SamePassword

single :: [a] -> Maybe a
single [x] = Just x
single _   = Nothing

data Id a = Id
    { unId    :: a
    , idKeyId :: Maybe BS.ByteString
    , idName  :: Maybe String
    }

mkId :: a -> Bag info -> Id a
mkId val bag = val `seq` Id val (getLocalKeyId attrs) (getFriendlyName attrs)
  where attrs = bagAttributes bag

decode :: ParseASN1Object [ASN1Event] obj => BS.ByteString -> Either StoreError obj
decode = decodeASN1Object

parseOctetStringObject :: (Monoid e, ParseASN1Object [ASN1Event] obj)
                       => String -> ParseASN1 e obj
parseOctetStringObject name = do
    OctetString bs <- getNext
    case decode bs of
        Left e  -> throwParseError (name ++ ": " ++ show e)
        Right c -> return c

buildCertificateChain :: X509.SignedCertificate -> [X509.SignedCertificate]
                      -> X509.CertificateChain
buildCertificateChain leaf authorities =
    X509.CertificateChain (leaf : findAuthorities leaf authorities)
  where
    findAuthorities cert others
        | subject cert == issuer cert = []
        | otherwise                   =
            case partition (\c -> subject c == issuer cert) others of
                ([c], others') -> c : findAuthorities c others'
                _              -> []

    signedCert = X509.signedObject . X509.getSigned

    subject c = X509.certSubjectDN (signedCert c)
    issuer c  = X509.certIssuerDN (signedCert c)
