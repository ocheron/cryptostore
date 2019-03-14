-- |
-- Module      : Crypto.Store.CMS.Info
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- CMS content information.
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.Store.CMS.Info
    ( ContentInfo(..)
    , getContentType
    , EncapsulatedContent
    , SignedData(..)
    , DigestedData(..)
    , AuthenticatedData(..)
    ) where

import Control.Applicative
import Control.Monad

import           Data.ASN1.Types
import           Data.ByteString (ByteString)
import qualified Data.ByteArray as B
import           Data.Maybe (fromMaybe)

import Crypto.Cipher.Types
import Crypto.Hash hiding (MD5)

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Attribute
import Crypto.Store.CMS.AuthEnveloped
import Crypto.Store.CMS.Encrypted
import Crypto.Store.CMS.Enveloped
import Crypto.Store.CMS.OriginatorInfo
import Crypto.Store.CMS.Signed
import Crypto.Store.CMS.Type
import Crypto.Store.CMS.Util

-- | Get the type of a content info.
getContentType :: ContentInfo -> ContentType
getContentType (DataCI _)              = DataType
getContentType (SignedDataCI _)        = SignedDataType
getContentType (EnvelopedDataCI _)     = EnvelopedDataType
getContentType (DigestedDataCI _)      = DigestedDataType
getContentType (EncryptedDataCI _)     = EncryptedDataType
getContentType (AuthenticatedDataCI _) = AuthenticatedDataType
getContentType (AuthEnvelopedDataCI _) = AuthEnvelopedDataType


-- | Encapsulated content.
type EncapsulatedContent = ByteString

-- ContentInfo

-- | CMS content information.
data ContentInfo = DataCI ByteString
                   -- ^ Arbitrary octet string
                 | SignedDataCI SignedData
                   -- ^ Signed content info
                 | EnvelopedDataCI (EnvelopedData EncryptedContent)
                   -- ^ Enveloped content info
                 | DigestedDataCI DigestedData
                   -- ^ Content info with associated digest
                 | EncryptedDataCI (EncryptedData EncryptedContent)
                   -- ^ Encrypted content info
                 | AuthenticatedDataCI AuthenticatedData
                   -- ^ Authenticatedcontent info
                 | AuthEnvelopedDataCI (AuthEnvelopedData EncryptedContent)
                   -- ^ Authenticated-enveloped content info
                 deriving (Show,Eq)

instance ProduceASN1Object ASN1P ContentInfo where
    asn1s ci = asn1Container Sequence (oid . cont)
      where oid = gOID $ getObjectID $ getContentType ci
            cont = asn1Container (Container Context 0) inner
            inner =
                case ci of
                    DataCI bs              -> dataASN1S bs
                    SignedDataCI ed        -> asn1s ed
                    EnvelopedDataCI ed     -> asn1s ed
                    DigestedDataCI dd      -> asn1s dd
                    EncryptedDataCI ed     -> asn1s ed
                    AuthenticatedDataCI ad -> asn1s ad
                    AuthEnvelopedDataCI ae -> asn1s ae

instance ParseASN1Object [ASN1Event] ContentInfo where
    parse =
        onNextContainer Sequence $ do
            OID oid <- getNext
            withObjectID "content type" oid $ \ct ->
                onNextContainer (Container Context 0) (parseInner ct)
      where
        parseInner DataType              = DataCI <$> parseData
        parseInner SignedDataType        = SignedDataCI <$> parse
        parseInner EnvelopedDataType     = EnvelopedDataCI <$> parse
        parseInner DigestedDataType      = DigestedDataCI <$> parse
        parseInner EncryptedDataType     = EncryptedDataCI <$> parse
        parseInner AuthenticatedDataType = AuthenticatedDataCI <$> parse
        parseInner AuthEnvelopedDataType = AuthEnvelopedDataCI <$> parse


-- Data

dataASN1S :: ASN1Elem e => ByteString -> ASN1Stream e
dataASN1S = gOctetString

parseData :: Monoid e => ParseASN1 e ByteString
parseData = do
    next <- getNext
    case next of
        OctetString bs -> return bs
        _              -> throwParseError "Data: parsed unexpected content"


-- SignedData

-- | Signed content information.
data SignedData = SignedData
    { sdDigestAlgorithms :: [DigestAlgorithm]      -- ^ Digest algorithms
    , sdContentType :: ContentType                 -- ^ Inner content type
    , sdEncapsulatedContent :: EncapsulatedContent -- ^ Encapsulated content
    , sdCertificates :: [CertificateChoice]        -- ^ The collection of certificates
    , sdCRLs  :: [RevocationInfoChoice]            -- ^ The collection of CRLs
    , sdSignerInfos :: [SignerInfo]                -- ^ Per-signer information
    }
    deriving (Show,Eq)

instance ProduceASN1Object ASN1P SignedData where
    asn1s SignedData{..} =
        asn1Container Sequence (ver . dig . ci . certs . crls . sis)
      where
        ver = gIntVal v
        dig = asn1Container Set (digestTypesASN1S sdDigestAlgorithms)
        ci  = encapsulatedContentInfoASN1S sdContentType sdEncapsulatedContent
        certs = gen 0 sdCertificates
        crls  = gen 1 sdCRLs
        sis = asn1Container Set (asn1s sdSignerInfos)

        gen tag list
            | null list = id
            | otherwise = asn1Container (Container Context tag) (asn1s list)

        v | hasChoiceOther sdCertificates = 5
          | hasChoiceOther sdCRLs         = 5
          | any isVersion3 sdSignerInfos  = 3
          | sdContentType == DataType     = 1
          | otherwise                     = 3


instance ParseASN1Object [ASN1Event] SignedData where
    parse =
        onNextContainer Sequence $ do
            IntVal v <- getNext
            when (v > 5) $
                throwParseError ("SignedData: parsed invalid version: " ++ show v)
            dig <- onNextContainer Set parseDigestTypes
            (ct, bs) <- parseEncapsulatedContentInfo
            certs <- parseOptList 0
            crls  <- parseOptList 1
            sis <- onNextContainer Set parse
            return SignedData { sdDigestAlgorithms = dig
                              , sdContentType = ct
                              , sdEncapsulatedContent = bs
                              , sdCertificates = certs
                              , sdCRLs = crls
                              , sdSignerInfos = sis
                              }
      where
        parseOptList tag =
            fromMaybe [] <$> onNextContainerMaybe (Container Context tag) parse

digestTypesASN1S :: ASN1Elem e => [DigestAlgorithm] -> ASN1Stream e
digestTypesASN1S list cont = foldr (algorithmASN1S Sequence) cont list

parseDigestTypes :: Monoid e => ParseASN1 e [DigestAlgorithm]
parseDigestTypes = getMany (parseAlgorithm Sequence)


-- DigestedData

-- | Digested content information.
data DigestedData = forall hashAlg. HashAlgorithm hashAlg => DigestedData
    { ddDigestAlgorithm :: DigestProxy hashAlg     -- ^ Digest algorithm
    , ddContentType :: ContentType                 -- ^ Inner content type
    , ddEncapsulatedContent :: EncapsulatedContent -- ^ Encapsulated content
    , ddDigest :: Digest hashAlg                   -- ^ Digest value
    }

instance Show DigestedData where
    showsPrec d DigestedData{..} = showParen (d > 10) $
        showString "DigestedData "
            . showString "{ ddDigestAlgorithm = " . shows ddDigestAlgorithm
            . showString ", ddContentType = " . shows ddContentType
            . showString ", ddEncapsulatedContent = " . shows ddEncapsulatedContent
            . showString ", ddDigest = " . shows ddDigest
            . showString " }"

instance Eq DigestedData where
    DigestedData a1 t1 e1 d1 == DigestedData a2 t2 e2 d2 =
        DigestAlgorithm a1 == DigestAlgorithm a2 && d1 `B.eq` d2 && t1 == t2 && e1 == e2

instance ASN1Elem e => ProduceASN1Object e DigestedData where
    asn1s DigestedData{..} =
        asn1Container Sequence (ver . alg . ci . dig)
      where
        v = if ddContentType == DataType then 0 else 2
        d = DigestAlgorithm ddDigestAlgorithm

        ver = gIntVal v
        alg = algorithmASN1S Sequence d
        ci  = encapsulatedContentInfoASN1S ddContentType ddEncapsulatedContent
        dig = gOctetString (B.convert ddDigest)

instance Monoid e => ParseASN1Object e DigestedData where
    parse =
        onNextContainer Sequence $ do
            IntVal v <- getNext
            when (v /= 0 && v /= 2) $
                throwParseError ("DigestedData: parsed invalid version: " ++ show v)
            alg <- parseAlgorithm Sequence
            (ct, bs) <- parseEncapsulatedContentInfo
            OctetString digValue <- getNext
            case alg of
                DigestAlgorithm digAlg ->
                    case digestFromByteString digValue of
                        Nothing -> throwParseError "DigestedData: parsed invalid digest"
                        Just d  ->
                            return DigestedData { ddDigestAlgorithm = digAlg
                                                , ddContentType = ct
                                                , ddEncapsulatedContent = bs
                                                , ddDigest = d
                                                }


-- Authenticated data

-- | Authenticated content information.
data AuthenticatedData = AuthenticatedData
    { adOriginatorInfo :: OriginatorInfo
      -- ^ Optional information about the originator
    , adRecipientInfos :: [RecipientInfo]
      -- ^ Information for recipients, allowing to authenticate the content
    , adMACAlgorithm :: MACAlgorithm
      -- ^ MAC algorithm
    , adDigestAlgorithm :: Maybe DigestAlgorithm
      -- ^ Optional digest algorithm
    , adContentType :: ContentType
      -- ^ Inner content type
    , adEncapsulatedContent :: EncapsulatedContent
      -- ^ Encapsulated content
    , adAuthAttrs :: [Attribute]
      -- ^ Optional authenticated attributes
    , adMAC :: MessageAuthenticationCode
      -- ^ Message authentication code
    , adUnauthAttrs :: [Attribute]
      -- ^ Optional unauthenticated attributes
    }
    deriving (Show,Eq)

instance ProduceASN1Object ASN1P AuthenticatedData where
    asn1s AuthenticatedData{..} =
        asn1Container Sequence (ver . oi . ris . alg . dig . ci . aa . tag . ua)
      where
        ver = gIntVal v
        ris = asn1Container Set (asn1s adRecipientInfos)
        alg = algorithmASN1S Sequence adMACAlgorithm
        dig = algorithmMaybeASN1S (Container Context 1) adDigestAlgorithm
        ci  = encapsulatedContentInfoASN1S adContentType adEncapsulatedContent
        aa  = attributesASN1S(Container Context 2) adAuthAttrs
        tag = gOctetString (B.convert adMAC)
        ua  = attributesASN1S (Container Context 3) adUnauthAttrs

        oi | adOriginatorInfo == mempty = id
           | otherwise = originatorInfoASN1S (Container Context 0) adOriginatorInfo

        v | hasChoiceOther adOriginatorInfo = 3
          | otherwise                       = 0

instance ParseASN1Object [ASN1Event] AuthenticatedData where
    parse =
        onNextContainer Sequence $ do
            IntVal v <- getNext
            when (v `notElem` [0, 1, 3]) $
                throwParseError ("AuthenticatedData: parsed invalid version: " ++ show v)
            oi <- parseOriginatorInfo (Container Context 0) <|> return mempty
            ris <- onNextContainer Set parse
            alg <- parseAlgorithm Sequence
            dig <- parseAlgorithmMaybe (Container Context 1)
            (ct, bs) <- parseEncapsulatedContentInfo
            aAttrs <- parseAttributes (Container Context 2)
            OctetString tag <- getNext
            uAttrs <- parseAttributes (Container Context 3)
            return AuthenticatedData { adOriginatorInfo = oi
                                     , adRecipientInfos = ris
                                     , adMACAlgorithm = alg
                                     , adDigestAlgorithm = dig
                                     , adContentType = ct
                                     , adEncapsulatedContent = bs
                                     , adAuthAttrs = aAttrs
                                     , adMAC = AuthTag $ B.convert tag
                                     , adUnauthAttrs = uAttrs
                                     }


-- Utilities

encapsulatedContentInfoASN1S :: ASN1Elem e => ContentType -> EncapsulatedContent -> ASN1Stream e
encapsulatedContentInfoASN1S ct bs = asn1Container Sequence (oid . cont)
  where oid = gOID (getObjectID ct)
        cont = asn1Container (Container Context 0) inner
        inner = gOctetString bs

parseEncapsulatedContentInfo :: Monoid e => ParseASN1 e (ContentType, EncapsulatedContent)
parseEncapsulatedContentInfo =
    onNextContainer Sequence $ do
        OID oid <- getNext
        withObjectID "content type" oid $ \ct ->
            onNextContainer (Container Context 0) (parseInner ct)
  where
    parseInner ct = do
        bs <- parseContentSingle <|> parseContentChunks
        return (ct, bs)

    parseContentSingle = do { OctetString bs <- getNext; return bs }
    parseContentChunks = onNextContainer (Container Universal 4) $
        B.concat <$> getMany parseContentSingle
