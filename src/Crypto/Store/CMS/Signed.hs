-- |
-- Module      : Crypto.Store.CMS.Signed
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
--
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Store.CMS.Signed
    ( SignerInfo(..)
    , SignerIdentifier(..)
    , IssuerAndSerialNumber(..)
    , isVersion3
    , ProducerOfSI
    , ConsumerOfSI
    , certSigner
    , withPublicKey
    , withSignerKey
    ) where

import Control.Applicative
import Control.Monad

import Data.ASN1.Types
import Data.ByteString (ByteString)
import Data.List
import Data.Maybe
import Data.X509

import Crypto.Random (MonadRandom)

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.AuthEnveloped
import Crypto.Store.CMS.Attribute
import Crypto.Store.CMS.Enveloped
import Crypto.Store.CMS.OriginatorInfo
import Crypto.Store.CMS.Type
import Crypto.Store.CMS.Util

-- | Information related to a signer of a 'Crypto.Store.CMS.SignedData'.  An
-- element contains the signature material that was produced.
data SignerInfo = SignerInfo
    { siSignerId :: SignerIdentifier
      -- ^ Identifier of the signer certificate
    , siDigestAlgorithm :: DigestType
      -- ^ Digest algorithm used for the signature
    , siSignedAttrs :: [Attribute]
      -- ^ Optional signed attributes
    , siSignatureAlg :: SignatureAlg
      -- ^ Algorithm used for signature
    , siSignature :: SignatureValue
      -- ^ The signature value
    , siUnsignedAttrs :: [Attribute]
      -- ^ Optional unsigned attributes
    }
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e SignerInfo where
    asn1s SignerInfo{..} =
        asn1Container Sequence (ver . sid . dig . sa . alg . sig . ua)
      where
        ver = gIntVal (getVersion siSignerId)
        sid = asn1s siSignerId
        dig = algorithmASN1S Sequence siDigestAlgorithm
        sa  = attributesASN1S (Container Context 0) siSignedAttrs
        alg = algorithmASN1S Sequence siSignatureAlg
        sig = gOctetString siSignature
        ua  = attributesASN1S (Container Context 1) siUnsignedAttrs

instance Monoid e => ParseASN1Object e SignerInfo where
    parse = onNextContainer Sequence $ do
        IntVal v <- getNext
        when (v /= 1 && v /= 3) $
            throwParseError ("SignerInfo: parsed invalid version: " ++ show v)
        sid <- parse
        dig <- parseAlgorithm Sequence
        sAttrs <- parseAttributes (Container Context 0)
        alg <- parseAlgorithm Sequence
        (OctetString sig) <- getNext
        uAttrs <- parseAttributes (Container Context 1)
        return SignerInfo { siSignerId = sid
                          , siDigestAlgorithm = dig
                          , siSignedAttrs = sAttrs
                          , siSignatureAlg = alg
                          , siSignature = sig
                          , siUnsignedAttrs = uAttrs
                          }

getVersion :: SignerIdentifier -> Integer
getVersion (SignerIASN _) = 1
getVersion (SignerSKI _)  = 3

-- | Return true when the signer info has version 3.
isVersion3 :: SignerInfo -> Bool
isVersion3 = (== 3) . getVersion . siSignerId

-- | Union type related to identification of the signer certificate.
data SignerIdentifier
    = SignerIASN IssuerAndSerialNumber  -- ^ Issuer and Serial Number
    | SignerSKI  ByteString             -- ^ Subject Key Identifier
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e SignerIdentifier where
    asn1s (SignerIASN iasn) = asn1s iasn
    asn1s (SignerSKI  ski)  = asn1Container (Container Context 0)
                                  (gOctetString ski)

instance Monoid e => ParseASN1Object e SignerIdentifier where
    parse = parseIASN <|> parseSKI
      where parseIASN = SignerIASN <$> parse
            parseSKI  = SignerSKI  <$>
                onNextContainer (Container Context 0) parseBS
            parseBS = do { OctetString bs <- getNext; return bs }

-- | Try to find a certificate with the specified identifier and return its
-- public key when found.
findSigner :: SignerIdentifier -> [SignedCertificate] -> Maybe PubKey
findSigner (SignerIASN iasn) certs =
    certPubKey <$> find matchIASN (map (signedObject . getSigned) certs)
  where
    matchIASN c =
        (iasnIssuer iasn, iasnSerial iasn) == (certIssuerDN c, certSerial c)
findSigner (SignerSKI  ski) certs =
    certPubKey <$> find matchSKI (map (signedObject . getSigned) certs)
  where
    matchSKI c =
        case extensionGet (certExtensions c) of
            Just (ExtSubjectKeyId idBs) -> idBs == ski
            Nothing                     -> False

-- | Function able to produce a 'SignerInfo'.
type ProducerOfSI m = ContentType -> ByteString -> m (Either String (SignerInfo, [CertificateChoice], [RevocationInfoChoice]))

-- | Function able to consume a 'SignerInfo'.
type ConsumerOfSI = ContentType -> ByteString -> SignerInfo -> [CertificateChoice] -> [RevocationInfoChoice] -> Bool

-- | Create a signer info with the specified signature algorithm and
-- credentials.
--
-- Two lists of optional attributes can be provided.  The attributes will be
-- part of message signature when provided in the first list.
--
-- When the first list of attributes is provided, even empty list, signature is
-- computed from a digest of the content.  When the list of attributes is
-- 'Nothing', no intermediate digest is used and the signature is computed from
-- the full message.
certSigner :: MonadRandom m
           => SignatureAlg
           -> PrivKey
           -> CertificateChain
           -> Maybe [Attribute]
           -> [Attribute]
           -> ProducerOfSI m
certSigner alg priv (CertificateChain chain) sAttrsM uAttrs ct msg =
    fmap build <$> generate
  where
    md   = digest dig msg
    def  = DigestType Crypto.Store.CMS.Algorithms.SHA256
    cert = head chain
    obj  = signedObject (getSigned cert)
    isn  = IssuerAndSerialNumber (certIssuerDN obj) (certSerial obj)

    (dig, alg') = signatureResolveHash def alg

    (sAttrs, input) =
        case sAttrsM of
            Nothing    -> ([], msg)
            Just attrs ->
                let l = setContentTypeAttr ct $ setMessageDigestAttr md attrs
                 in (l, encodeAuthAttrs l)

    generate  = signatureGenerate alg' priv input
    build sig =
        let si = SignerInfo { siSignerId = SignerIASN isn
                            , siDigestAlgorithm = dig
                            , siSignedAttrs = sAttrs
                            , siSignatureAlg = alg
                            , siSignature = sig
                            , siUnsignedAttrs = uAttrs
                            }
         in (si, map CertificateCertificate chain, [])

-- | Verify that the signature was produced from the specified public key.
-- Ignores all certificates and CRLs contained in the signed data.
withPublicKey :: PubKey -> ConsumerOfSI
withPublicKey pub ct msg SignerInfo{..} _ _ =
    fromMaybe False $ do
        guard (noAttr || attrMatch)
        alg <- signatureCheckHash siDigestAlgorithm siSignatureAlg
        return (signatureVerify alg pub input siSignature)
  where
    noAttr    = null siSignedAttrs
    mdMatch   = mdAttr == Just (digest siDigestAlgorithm msg)
    attrMatch = ctAttr == Just ct && mdMatch
    mdAttr    = getMessageDigestAttr siSignedAttrs
    ctAttr    = getContentTypeAttr siSignedAttrs
    input     = if noAttr then msg else encodeAuthAttrs siSignedAttrs

-- | Verify that the signature is valid with one of the X.509 certificates
-- contained in the signed data, but does not validate that the certificates are
-- valid.  All transmitted certificates are implicitely trusted and all CRLs are
-- ignored.
withSignerKey :: ConsumerOfSI
withSignerKey ct msg SignerInfo{..} certs crls =
    fromMaybe False $ do
        pub <- findSigner siSignerId x509Certificates
        return (withPublicKey pub ct msg SignerInfo{..} certs crls)
  where
    x509Certificates = mapMaybe asX509 certs

    asX509 (CertificateCertificate c) = Just c
    asX509 _                          = Nothing
