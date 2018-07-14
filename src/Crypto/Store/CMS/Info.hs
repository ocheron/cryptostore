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
    , DigestedData(..)
    , encapsulate
    , decapsulate
    ) where

import Control.Monad

import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types
import           Data.ByteString (ByteString)
import qualified Data.ByteArray as B

import Crypto.Hash hiding (MD5)

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Encrypted
import Crypto.Store.CMS.Enveloped
import Crypto.Store.CMS.Type
import Crypto.Store.CMS.Util

-- | Get the type of a content info.
getContentType :: ContentInfo -> ContentType
getContentType (DataCI _)              = DataType
getContentType (EnvelopedDataCI _)     = EnvelopedDataType
getContentType (DigestedDataCI _)      = DigestedDataType
getContentType (EncryptedDataCI _)     = EncryptedDataType


-- ContentInfo

-- | CMS content information.
data ContentInfo = DataCI ByteString                     -- ^ Arbitrary octet string
                 | EnvelopedDataCI EnvelopedData         -- ^ Enveloped content info
                 | DigestedDataCI DigestedData           -- ^ Content info with associated digest
                 | EncryptedDataCI EncryptedData         -- ^ Encrypted content info
                 deriving (Show,Eq)

instance ProduceASN1Object ContentInfo where
    asn1s ci = asn1Container Sequence (oid . cont)
      where oid = gOID $ getObjectID $ getContentType ci
            cont = asn1Container (Container Context 0) inner
            inner =
                case ci of
                    DataCI bs              -> dataASN1S bs
                    EnvelopedDataCI ed     -> asn1s ed
                    DigestedDataCI dd      -> asn1s dd
                    EncryptedDataCI ed     -> asn1s ed

instance Monoid e => ParseASN1Object e ContentInfo where
    parse =
        onNextContainer Sequence $ do
            OID oid <- getNext
            withObjectID "content type" oid $ \ct ->
                onNextContainer (Container Context 0) (parseInner ct)
      where
        parseInner DataType              = DataCI <$> parseData
        parseInner EnvelopedDataType     = EnvelopedDataCI <$> parse
        parseInner DigestedDataType      = DigestedDataCI <$> parse
        parseInner EncryptedDataType     = EncryptedDataCI <$> parse

instance ASN1Object ContentInfo where
    toASN1   = asn1s
    fromASN1 = runParseASN1State parse


-- Data

dataASN1S :: ByteString -> ASN1S
dataASN1S = gOctetString

parseData :: Monoid e => ParseASN1 e ByteString
parseData = do
    next <- getNext
    case next of
        OctetString bs -> return bs
        _              -> throwParseError "Data: parsed unexpected content"


-- DigestedData

-- | Digested content information.
data DigestedData = forall hashAlg. HashAlgorithm hashAlg => DigestedData
    { ddDigestAlgorithm :: DigestAlgorithm hashAlg -- ^ Digest algorithm
    , ddContentInfo :: ContentInfo                 -- ^ Inner content info
    , ddDigest :: Digest hashAlg                   -- ^ Digest value
    }

instance Show DigestedData where
    showsPrec d DigestedData{..} = showParen (d > 10) $
        showString "DigestedData "
            . showString "{ ddDigestAlgorithm = " . shows ddDigestAlgorithm
            . showString ", ddContentInfo = " . shows ddContentInfo
            . showString ", ddDigest = " . shows ddDigest
            . showString " }"

instance Eq DigestedData where
    DigestedData a1 i1 d1 == DigestedData a2 i2 d2 =
        DigestType a1 == DigestType a2 && d1 `eqBA` d2 && i1 == i2

instance ProduceASN1Object DigestedData where
    asn1s DigestedData{..} =
        asn1Container Sequence (ver . alg . ci . dig)
      where
        v = if isData ddContentInfo then 0 else 2
        d = DigestType ddDigestAlgorithm

        ver = gIntVal v
        alg = asn1Container Sequence (digestTypeASN1S d)
        ci  = encapsulatedContentInfoASN1S ddContentInfo
        dig = gOctetString (B.convert ddDigest)

        isData (DataCI _) = True
        isData _          = False

instance Monoid e => ParseASN1Object e DigestedData where
    parse =
        onNextContainer Sequence $ do
            IntVal v <- getNext
            when (v /= 0 && v /= 2) $
                throwParseError ("DigestedData: parsed invalid version: " ++ show v)
            alg <- onNextContainer Sequence parseDigestType
            inner <- parseEncapsulatedContentInfo
            OctetString digest <- getNext
            case alg of
                DigestType digAlg ->
                    case digestFromByteString digest of
                        Nothing -> throwParseError "DigestedData: parsed invalid digest"
                        Just d  ->
                            return DigestedData { ddDigestAlgorithm = digAlg
                                                , ddContentInfo = inner
                                                , ddDigest = d
                                                }

digestTypeASN1S :: DigestType -> ASN1S
digestTypeASN1S d = gOID (getObjectID d) . param
  where
    -- MD5 has NULL parameter, other algorithms have no parameter
    param = case d of
                DigestType MD5 -> gNull
                _              -> id

parseDigestType :: Monoid e => ParseASN1 e DigestType
parseDigestType = do
    OID oid <- getNext
    withObjectID "digest algorithm" oid $ \alg -> do
        _ <- getNextMaybe nullOrNothing
        return alg


-- Utilities

decode :: ParseASN1 () a -> ByteString -> Either String a
decode parser bs = vals >>= runParseASN1 parser
  where vals = either (Left . showerr) Right (decodeASN1' BER bs)
        showerr err = "Unable to decode encapsulated ASN.1: " ++ show err

-- | Encode the information for encapsulation in another content info.
encapsulate :: ContentInfo -> ByteString
encapsulate (DataCI bs)              = bs
encapsulate (EnvelopedDataCI ed)     = encodeASN1Object ed
encapsulate (DigestedDataCI dd)      = encodeASN1Object dd
encapsulate (EncryptedDataCI ed)     = encodeASN1Object ed

-- | Decode the information from encapsulated content.
decapsulate :: ContentType -> ByteString -> Either String ContentInfo
decapsulate DataType bs              = pure (DataCI bs)
decapsulate EnvelopedDataType bs     = EnvelopedDataCI <$> decode parse bs
decapsulate DigestedDataType bs      = DigestedDataCI <$> decode parse bs
decapsulate EncryptedDataType bs     = EncryptedDataCI <$> decode parse bs

encapsulatedContentInfoASN1S :: ContentInfo -> ASN1S
encapsulatedContentInfoASN1S ci = asn1Container Sequence (oid . cont)
  where oid = gOID $ getObjectID $ getContentType ci
        cont = asn1Container (Container Context 0) inner
        inner = gOctetString (encapsulate ci)

parseEncapsulatedContentInfo :: Monoid e => ParseASN1 e ContentInfo
parseEncapsulatedContentInfo =
    onNextContainer Sequence $ do
        OID oid <- getNext
        withObjectID "content type" oid $ \ct ->
            onNextContainer (Container Context 0) (parseInner ct)
  where
    parseInner ct = do
        OctetString bs <- getNext
        case decapsulate ct bs of
            Left err -> throwParseError err
            Right ci -> return ci
