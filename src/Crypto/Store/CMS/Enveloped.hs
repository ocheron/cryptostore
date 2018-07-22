-- |
-- Module      : Crypto.Store.CMS.Enveloped
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
--
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Store.CMS.Enveloped
    ( EncryptedKey
    , RecipientInfo(..)
    , EnvelopedData(..)
    , ProducerOfRI
    , ConsumerOfRI
    -- * Key Transport recipients
    , KTRecipientInfo(..)
    , RecipientIdentifier(..)
    , IssuerAndSerialNumber(..)
    , forKeyTransRecipient
    , withRecipientKeyTrans
    -- * Key Encryption Key recipients
    , KeyEncryptionKey
    , KEKRecipientInfo(..)
    , KEKIdentifier(..)
    , OtherKeyAttribute(..)
    , forKeyRecipient
    , withRecipientKey
    -- * Password recipients
    , Password
    , PasswordRecipientInfo(..)
    , forPasswordRecipient
    , withRecipientPassword
    ) where

import Control.Applicative
import Control.Monad

import Data.ASN1.Types
import Data.ByteString (ByteString)
import Data.Maybe (fromMaybe)
import Data.X509

import Time.Types

import Crypto.Random (MonadRandom)

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Attribute
import Crypto.Store.CMS.Encrypted
import Crypto.Store.CMS.OriginatorInfo
import Crypto.Store.CMS.Type
import Crypto.Store.CMS.Util

-- | Encrypted key.
type EncryptedKey = ByteString

-- | Key used for key encryption.
type KeyEncryptionKey = ByteString

-- | A password stored as a sequence of UTF-8 bytes.
--
-- Some key-derivation functions add restrictions to what characters
-- are supported.
type Password = ByteString

-- | Union type related to identification of the recipient.
data RecipientIdentifier
    = RecipientIASN IssuerAndSerialNumber  -- ^ Issuer and Serial Number
    | RecipientSKI  ByteString             -- ^ Subject Key Identifier
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e RecipientIdentifier where
    asn1s (RecipientIASN iasn) = asn1s iasn
    asn1s (RecipientSKI  ski)  = asn1Container (Container Context 0)
                                    (gOctetString ski)

instance Monoid e => ParseASN1Object e RecipientIdentifier where
    parse = parseIASN <|> parseSKI
      where parseIASN = RecipientIASN <$> parse
            parseSKI  = RecipientSKI  <$>
                onNextContainer (Container Context 0) parseBS
            parseBS = do { OctetString bs <- getNext; return bs }

getKTVersion :: RecipientIdentifier -> Integer
getKTVersion (RecipientIASN _) = 0
getKTVersion (RecipientSKI _)  = 2

-- | Identification of a certificate using the issuer DN and serial number.
data IssuerAndSerialNumber = IssuerAndSerialNumber
    { iasnIssuer :: DistinguishedName
      -- ^ Distinguished name of the certificate issuer
    , iasnSerial :: Integer
      -- ^ Issuer-specific certificate serial number
    }
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e IssuerAndSerialNumber where
    asn1s IssuerAndSerialNumber{..} =
        asn1Container Sequence (asn1s iasnIssuer . gIntVal iasnSerial)

instance Monoid e => ParseASN1Object e IssuerAndSerialNumber where
    parse = onNextContainer Sequence $ do
        i <- parse
        IntVal s <- getNext
        return IssuerAndSerialNumber { iasnIssuer = i
                                     , iasnSerial = s
                                     }

-- | Additional information in a 'KEKIdentifier'.
data OtherKeyAttribute = OtherKeyAttribute
    { keyAttrId :: OID    -- ^ attribute identifier
    , keyAttr   :: [ASN1] -- ^ attribute value
    }
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e OtherKeyAttribute where
    asn1s OtherKeyAttribute{..} = asn1Container Sequence (attrId . attr)
      where attrId = gOID keyAttrId
            attr   = gMany keyAttr

instance Monoid e => ParseASN1Object e OtherKeyAttribute where
    parse = onNextContainer Sequence $ do
        OID attrId <- getNext
        attr <- getMany getNext
        return OtherKeyAttribute { keyAttrId = attrId, keyAttr = attr }

-- | Key Encryption Key identifier and optional attributes.
data KEKIdentifier = KEKIdentifier
    { kekKeyIdentifier :: ByteString      -- ^ identifier of the key
    , kekDate :: Maybe DateTime           -- ^ optional timestamp
    , kekOther :: Maybe OtherKeyAttribute -- ^ optional information
    }
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e KEKIdentifier where
    asn1s KEKIdentifier{..} = asn1Container Sequence (keyId . date . other)
      where
        keyId = gOctetString kekKeyIdentifier
        date  = optASN1S kekDate $ \v -> gASN1Time TimeGeneralized v Nothing
        other = optASN1S kekOther asn1s

instance Monoid e => ParseASN1Object e KEKIdentifier where
    parse = onNextContainer Sequence $ do
        OctetString keyId <- getNext
        date <- getNextMaybe dateTimeOrNothing
        b <- hasNext
        other <- if b then Just <$> parse else return Nothing
        return KEKIdentifier { kekKeyIdentifier = keyId
                             , kekDate = date
                             , kekOther = other
                             }

-- | Recipient using key transport.
data KTRecipientInfo = KTRecipientInfo
    { ktRid :: RecipientIdentifier                 -- ^ identifier of recipient
    , ktKeyTransportParams :: KeyTransportParams   -- ^ key transport algorithm
    , ktEncryptedKey :: EncryptedKey               -- ^ encrypted content-encryption key
    }
    deriving (Show,Eq)

-- | Recipient using key encryption.
data KEKRecipientInfo = KEKRecipientInfo
    { kekId :: KEKIdentifier                        -- ^ identifier of key encryption key
    , kekKeyEncryptionParams :: KeyEncryptionParams -- ^ key encryption algorithm
    , kekEncryptedKey :: EncryptedKey               -- ^ encrypted content-encryption key
    }
    deriving (Show,Eq)

-- | Recipient using password-based protection.
data PasswordRecipientInfo = PasswordRecipientInfo
    { priKeyDerivationFunc :: KeyDerivationFunc     -- ^ function to derive key
    , priKeyEncryptionParams :: KeyEncryptionParams -- ^ key encryption algorithm
    , priEncryptedKey :: EncryptedKey               -- ^ encrypted content-encryption key
    }
    deriving (Show,Eq)

-- | Information for a recipient of an 'EnvelopedData'.  An element contains
-- the content-encryption key in encrypted form.
data RecipientInfo = KTRI KTRecipientInfo
                     -- ^ Recipient using key transport
                   | KEKRI KEKRecipientInfo
                     -- ^ Recipient using key encryption
                   | PasswordRI PasswordRecipientInfo
                     -- ^ Recipient using password-based protection
    deriving (Show,Eq)

instance ASN1Elem e => ProduceASN1Object e RecipientInfo where
    asn1s (KTRI KTRecipientInfo{..}) =
        asn1Container Sequence (ver . rid . ktp . ek)
      where
        ver = gIntVal (getKTVersion ktRid)
        rid = asn1s ktRid
        ktp = algorithmASN1S Sequence ktKeyTransportParams
        ek  = gOctetString ktEncryptedKey

    asn1s (KEKRI KEKRecipientInfo{..}) =
        asn1Container (Container Context 2) (ver . kid . kep . ek)
      where
        ver = gIntVal 4
        kid = asn1s kekId
        kep = algorithmASN1S Sequence kekKeyEncryptionParams
        ek  = gOctetString kekEncryptedKey

    asn1s (PasswordRI PasswordRecipientInfo{..}) =
        asn1Container (Container Context 3) (ver . kdf . kep . ek)
      where
        ver = gIntVal 0
        kdf = algorithmASN1S (Container Context 0) priKeyDerivationFunc
        kep = algorithmASN1S Sequence priKeyEncryptionParams
        ek  = gOctetString priEncryptedKey

instance Monoid e => ParseASN1Object e RecipientInfo where
    parse = do
        c <- onNextContainerMaybe Sequence parseKT
             `orElse` onNextContainerMaybe (Container Context 2) parseKEK
             `orElse` onNextContainerMaybe (Container Context 3) parsePassword
        case c of
            Just val -> return val
            Nothing  -> throwParseError "RecipientInfo: unable to parse"
      where
        parseKT = KTRI <$> do
            IntVal v <- getNext
            when (v `notElem` [0, 2]) $
                throwParseError ("RecipientInfo: parsed invalid KT version: " ++ show v)
            rid <- parse
            ktp <- parseAlgorithm Sequence
            (OctetString ek) <- getNext
            return KTRecipientInfo { ktRid = rid
                                   , ktKeyTransportParams = ktp
                                   , ktEncryptedKey = ek
                                   }

        parseKEK = KEKRI <$> do
            IntVal 4 <- getNext
            kid <- parse
            kep <- parseAlgorithm Sequence
            (OctetString ek) <- getNext
            return KEKRecipientInfo { kekId = kid
                                    , kekKeyEncryptionParams = kep
                                    , kekEncryptedKey = ek
                                    }

        parsePassword = PasswordRI <$> do
            IntVal 0 <- getNext
            kdf <- parseAlgorithm (Container Context 0)
            kep <- parseAlgorithm Sequence
            (OctetString ek) <- getNext
            return PasswordRecipientInfo { priKeyDerivationFunc = kdf
                                         , priKeyEncryptionParams = kep
                                         , priEncryptedKey = ek
                                         }

isVersion0 :: RecipientInfo -> Bool
isVersion0 (KTRI x)       = getKTVersion (ktRid x) == 0
isVersion0 (KEKRI _)      = False      -- because version is always 4
isVersion0 (PasswordRI _) = True       -- because version is always 0

isPwriOri :: RecipientInfo -> Bool
isPwriOri (KTRI _)       = False
isPwriOri (KEKRI _)      = False
isPwriOri (PasswordRI _) = True

-- | Enveloped content information.
data EnvelopedData = EnvelopedData
    { evOriginatorInfo :: OriginatorInfo
      -- ^ Optional information about the originator
    , evRecipientInfos :: [RecipientInfo]
      -- ^ Information for recipients, allowing to decrypt the content
    , evContentType :: ContentType
      -- ^ Inner content type
    , evContentEncryptionParams :: ContentEncryptionParams
      -- ^ Encryption algorithm
    , evEncryptedContent :: EncryptedContent
      -- ^ Encrypted content info
    , evUnprotectedAttrs :: [Attribute]
      -- ^ Optional unprotected attributes
    }
    deriving (Show,Eq)

instance ProduceASN1Object ASN1P EnvelopedData where
    asn1s EnvelopedData{..} =
        asn1Container Sequence (ver . oi . ris . eci . ua)
      where
        ver = gIntVal v
        ris = asn1Container Set (asn1s evRecipientInfos)
        eci = encryptedContentInfoASN1S
                  (evContentType, evContentEncryptionParams, evEncryptedContent)
        ua  = attributesASN1S (Container Context 1) evUnprotectedAttrs

        oi | evOriginatorInfo == mempty = id
           | otherwise = originatorInfoASN1S (Container Context 0) evOriginatorInfo

        v | hasChoiceOther evOriginatorInfo = 4
          | any isPwriOri evRecipientInfos  = 3
          | evOriginatorInfo /= mempty      = 2
          | not (null evUnprotectedAttrs)   = 2
          | all isVersion0 evRecipientInfos = 0
          | otherwise                       = 2

instance ParseASN1Object [ASN1Event] EnvelopedData where
    parse =
        onNextContainer Sequence $ do
            IntVal v <- getNext
            when (v > 4) $
                throwParseError ("EnvelopedData: parsed invalid version: " ++ show v)
            oi <- parseOriginatorInfo (Container Context 0) <|> return mempty
            ris <- onNextContainer Set parse
            (ct, params, ec) <- parseEncryptedContentInfo
            attrs <- parseAttributes (Container Context 1)
            return EnvelopedData { evOriginatorInfo = oi
                                 , evRecipientInfos = ris
                                 , evContentType = ct
                                 , evContentEncryptionParams = params
                                 , evEncryptedContent = ec
                                 , evUnprotectedAttrs = attrs
                                 }

-- | Function able to produce a 'RecipientInfo'.
type ProducerOfRI m = ContentEncryptionKey -> m (Either String RecipientInfo)

-- | Function able to consume a 'RecipientInfo'.
type ConsumerOfRI m = RecipientInfo -> m (Either String ContentEncryptionKey)

-- | Generate a Key Transport recipient from a certificate and
-- desired algorithm.  The recipient will contain certificate identifier.
--
-- This function can be used as parameter to 'Crypto.Store.CMS.envelopData'.
forKeyTransRecipient :: MonadRandom m
                     => SignedCertificate -> KeyTransportParams -> ProducerOfRI m
forKeyTransRecipient cert params inkey = do
    ek <- transportEncrypt params (certPubKey obj) inkey
    return (KTRI . build <$> ek)
  where
    obj = signedObject (getSigned cert)
    isn = IssuerAndSerialNumber (certIssuerDN obj) (certSerial obj)

    build ek = KTRecipientInfo
                  { ktRid = RecipientIASN isn
                  , ktKeyTransportParams = params
                  , ktEncryptedKey = ek
                  }

-- | Use a Key Transport recipient, knowing the private key.
--
-- This function can be used as parameter to
-- 'Crypto.Store.CMS.openEnvelopedData'.
withRecipientKeyTrans :: MonadRandom m => PrivKey -> ConsumerOfRI m
withRecipientKeyTrans privKey (KTRI KTRecipientInfo{..}) =
    transportDecrypt ktKeyTransportParams privKey ktEncryptedKey
withRecipientKeyTrans _ _ = pure (Left "Not a KT recipient")

-- | Generate a Key Encryption Key recipient from a key encryption key and
-- desired algorithm.  The recipient may identify the KEK that was used with
-- the supplied identifier.
--
-- This function can be used as parameter to 'Crypto.Store.CMS.envelopData'.
forKeyRecipient :: MonadRandom m
                => KeyEncryptionKey
                -> KEKIdentifier
                -> KeyEncryptionParams
                -> ProducerOfRI m
forKeyRecipient key kid params inkey = do
    ek <- keyEncrypt key params inkey
    return (KEKRI . build <$> ek)
  where
    build ek = KEKRecipientInfo
                   { kekId = kid
                   , kekKeyEncryptionParams = params
                   , kekEncryptedKey = ek
                   }

-- | Use a Key Encryption Key recipient, knowing the key encryption key.
--
-- This function can be used as parameter to
-- 'Crypto.Store.CMS.openEnvelopedData'.
withRecipientKey :: Applicative f => KeyEncryptionKey -> ConsumerOfRI f
withRecipientKey key (KEKRI KEKRecipientInfo{..}) =
    pure (keyDecrypt key kekKeyEncryptionParams kekEncryptedKey)
withRecipientKey _ _ = pure (Left "Not a KEK recipient")

-- | Generate a password recipient from a password.
--
-- This function can be used as parameter to 'Crypto.Store.CMS.envelopData'.
forPasswordRecipient :: MonadRandom m
                     => Password
                     -> KeyDerivationFunc
                     -> KeyEncryptionParams
                     -> ProducerOfRI m
forPasswordRecipient pwd kdf params inkey = do
    ek <- keyEncrypt derived params inkey
    return (PasswordRI . build <$> ek)
  where
    derived = kdfDerive kdf len pwd :: EncryptedKey
    len = fromMaybe (getMaximumKeySize params) (kdfKeyLength kdf)
    build ek = PasswordRecipientInfo
                   { priKeyDerivationFunc = kdf
                   , priKeyEncryptionParams = params
                   , priEncryptedKey = ek
                   }

-- | Use a password recipient, knowing the password.
--
-- This function can be used as parameter to
-- 'Crypto.Store.CMS.openEnvelopedData'.
withRecipientPassword :: Applicative f => Password -> ConsumerOfRI f
withRecipientPassword pwd (PasswordRI PasswordRecipientInfo{..}) =
    pure (keyDecrypt derived priKeyEncryptionParams priEncryptedKey)
  where
    derived = kdfDerive priKeyDerivationFunc len pwd :: EncryptedKey
    len = fromMaybe (getMaximumKeySize priKeyEncryptionParams)
                    (kdfKeyLength priKeyDerivationFunc)
withRecipientPassword _ _ = pure (Left "Not a password recipient")
