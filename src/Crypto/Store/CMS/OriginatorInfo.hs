-- |
-- Module      : Crypto.Store.CMS.OriginatorInfo
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
--
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Store.CMS.OriginatorInfo
    ( OriginatorInfo(..)
    , CertificateChoice(..)
    , OtherCertificateFormat(..)
    , RevocationInfoChoice(..)
    , OtherRevocationInfoFormat(..)
    , originatorInfoASN1S
    , parseOriginatorInfo
    , hasChoiceOther
    ) where

import Control.Applicative

import Data.ASN1.Types
import Data.Maybe (fromMaybe)
import Data.Semigroup
import Data.X509

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Util

-- | Data types where choice "other" is available.
class HasChoiceOther a where
    -- | Return true when choice "other" is selected.
    hasChoiceOther :: a -> Bool

instance (HasChoiceOther a, Foldable f) => HasChoiceOther (f a) where
    hasChoiceOther = any hasChoiceOther

-- | Information about the originator of the content info, to be used when
-- a key management algorithm requires this information.
data OriginatorInfo = OriginatorInfo
    { originatorCerts :: [CertificateChoice]
      -- ^ The collection of certificates
    , originatorCRLs  :: [RevocationInfoChoice]
      -- ^ The collection of CRLs
    }
    deriving (Show,Eq)

instance Semigroup OriginatorInfo where
    OriginatorInfo a b <> OriginatorInfo c d = OriginatorInfo (a <> c) (b <> d)

instance Monoid OriginatorInfo where
    mempty = OriginatorInfo [] []
    mappend (OriginatorInfo a b) (OriginatorInfo c d) =
        OriginatorInfo (mappend a c) (mappend b d)

instance HasChoiceOther OriginatorInfo where
    hasChoiceOther OriginatorInfo{..} =
        hasChoiceOther originatorCerts || hasChoiceOther originatorCRLs

instance ProduceASN1Object ASN1P OriginatorInfo where
    asn1s = originatorInfoASN1S Sequence

instance ParseASN1Object [ASN1Event] OriginatorInfo where
    parse = parseOriginatorInfo Sequence

-- | Generate ASN.1 with the specified constructed type for the originator
-- information.
originatorInfoASN1S :: ASN1ConstructionType -> OriginatorInfo -> ASN1PS
originatorInfoASN1S ty OriginatorInfo{..} =
    asn1Container ty $ gen 0 originatorCerts . gen 1 originatorCRLs
  where
    gen tag list
        | null list = id
        | otherwise = asn1Container (Container Context tag) (asn1s list)

-- | Parse originator information with the specified constructed type.
parseOriginatorInfo :: ASN1ConstructionType
                    -> ParseASN1 [ASN1Event] OriginatorInfo
parseOriginatorInfo ty = onNextContainer ty $ do
    certs <- parseOptList 0
    crls  <- parseOptList 1
    return OriginatorInfo { originatorCerts = certs
                          , originatorCRLs  = crls
                          }
  where
    parseOptList tag =
        fromMaybe [] <$> onNextContainerMaybe (Container Context tag) parse

-- | Union type related to certificate formats.
data CertificateChoice
    = CertificateCertificate SignedCertificate -- ^ X.509 certificate
    | CertificateOther OtherCertificateFormat  -- ^ Other format
    deriving (Show,Eq)

instance HasChoiceOther CertificateChoice where
    hasChoiceOther (CertificateOther _) = True
    hasChoiceOther _                    = False

instance ProduceASN1Object ASN1P CertificateChoice where
    asn1s (CertificateCertificate cert) = asn1s cert
    asn1s (CertificateOther other) =
        otherCertificateFormatASN1PS (Container Context 3) other

instance ParseASN1Object [ASN1Event] CertificateChoice where
    parse = parseMain <|> parseOther
      where parseMain  = CertificateCertificate <$> parse
            parseOther = CertificateOther <$>
                parseOtherCertificateFormat (Container Context 3)

-- | Union type related to revocation info formats.
data RevocationInfoChoice
    = RevocationInfoCRL SignedCRL
      -- ^ A CRL, ARL, Delta CRL, or an ACRL
    | RevocationInfoOther OtherRevocationInfoFormat
      -- ^ Other format
    deriving (Show,Eq)

instance HasChoiceOther RevocationInfoChoice where
    hasChoiceOther (RevocationInfoOther _) = True
    hasChoiceOther _                       = False

instance ProduceASN1Object ASN1P RevocationInfoChoice where
    asn1s (RevocationInfoCRL crl) = asn1s crl
    asn1s (RevocationInfoOther other) =
        otherRevocationInfoFormatASN1PS (Container Context 1) other

instance ParseASN1Object [ASN1Event] RevocationInfoChoice where
    parse = parseMain <|> parseOther
      where parseMain  = RevocationInfoCRL <$> parse
            parseOther = RevocationInfoOther <$>
                parseOtherRevocationInfoFormat (Container Context 1)

-- | Certificate information in a format not supported natively.
data OtherCertificateFormat = OtherCertificateFormat
    { otherCertFormat :: OID    -- ^ Format identifier
    , otherCertValues :: [ASN1] -- ^ ASN.1 values using this format
    }
    deriving (Show,Eq)

otherCertificateFormatASN1PS :: ASN1Elem e
                             => ASN1ConstructionType
                             -> OtherCertificateFormat
                             -> ASN1Stream e
otherCertificateFormatASN1PS ty OtherCertificateFormat{..} =
    asn1Container ty (f . v)
  where f = gOID otherCertFormat
        v = gMany otherCertValues

parseOtherCertificateFormat :: Monoid e
                            => ASN1ConstructionType
                            -> ParseASN1 e OtherCertificateFormat
parseOtherCertificateFormat ty = onNextContainer ty $ do
    OID f <- getNext
    v <- getMany getNext
    return OtherCertificateFormat { otherCertFormat = f
                                  , otherCertValues = v }

-- | Revocation information in a format not supported natively.
data OtherRevocationInfoFormat = OtherRevocationInfoFormat
    { otherRevInfoFormat :: OID    -- ^ Format identifier
    , otherRevInfoValues :: [ASN1] -- ^ ASN.1 values using this format
    }
    deriving (Show,Eq)

otherRevocationInfoFormatASN1PS :: ASN1Elem e
                                => ASN1ConstructionType
                                -> OtherRevocationInfoFormat
                                -> ASN1Stream e
otherRevocationInfoFormatASN1PS ty OtherRevocationInfoFormat{..} =
    asn1Container ty (f . v)
  where f = gOID otherRevInfoFormat
        v = gMany otherRevInfoValues

parseOtherRevocationInfoFormat :: Monoid e
                               => ASN1ConstructionType
                               -> ParseASN1 e OtherRevocationInfoFormat
parseOtherRevocationInfoFormat ty = onNextContainer ty $ do
    OID f <- getNext
    v <- getMany getNext
    return OtherRevocationInfoFormat { otherRevInfoFormat = f
                                     , otherRevInfoValues = v }
