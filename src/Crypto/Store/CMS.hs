-- |
-- Module      : Crypto.Store.CMS
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Cryptographic Message Syntax
--
-- * <https://tools.ietf.org/html/rfc5652 RFC 5652>: Cryptographic Message Syntax (CMS)
-- * <https://tools.ietf.org/html/rfc3370 RFC 3370>: Cryptographic Message Syntax (CMS) Algorithms
-- * <https://tools.ietf.org/html/rfc3560 RFC 3560>: Use of the RSAES-OAEP Key Transport Algorithm in the Cryptographic Message Syntax (CMS)
-- * <https://tools.ietf.org/html/rfc4056 RFC 4056>: Use of the RSASSA-PSS Signature Algorithm in Cryptographic Message Syntax (CMS)
-- * <https://tools.ietf.org/html/rfc3565 RFC 3565>: Use of the Advanced Encryption Standard (AES) Encryption Algorithm in Cryptographic Message Syntax (CMS)
-- * <https://tools.ietf.org/html/rfc5753 RFC 5753>: Use of Elliptic Curve Cryptography (ECC) Algorithms in Cryptographic Message Syntax (CMS)
-- * <https://tools.ietf.org/html/rfc5754 RFC 5754>: Using SHA2 Algorithms with Cryptographic Message Syntax
-- * <https://tools.ietf.org/html/rfc3211 RFC 3211>: Password-based Encryption for CMS
-- * <https://tools.ietf.org/html/rfc5083 RFC 5083>: Cryptographic Message Syntax (CMS) Authenticated-Enveloped-Data Content Type
-- * <https://tools.ietf.org/html/rfc5084 RFC 5084>: Using AES-CCM and AES-GCM Authenticated Encryption in the Cryptographic Message Syntax (CMS)
-- * <https://tools.ietf.org/html/rfc6476 RFC 6476>: Using Message Authentication Code (MAC) Encryption in the Cryptographic Message Syntax (CMS)
-- * <https://tools.ietf.org/html/rfc8103 RFC 8103>: Using ChaCha20-Poly1305 Authenticated Encryption in the Cryptographic Message Syntax (CMS)
-- * <https://tools.ietf.org/html/rfc8418 RFC 8418>: Use of the Elliptic Curve Diffie-Hellman Key Agreement Algorithm with X25519 and X448 in the Cryptographic Message Syntax (CMS)
-- * <https://tools.ietf.org/html/rfc8419 RFC 8419>: Use of Edwards-Curve Digital Signature Algorithm (EdDSA) Signatures in the Cryptographic Message Syntax (CMS)
-- * <https://tools.ietf.org/html/rfc8702 RFC 8702>: Use of the SHAKE One-Way Hash Functions in the Cryptographic Message Syntax (CMS)
{-# LANGUAGE RecordWildCards #-}
module Crypto.Store.CMS
    ( ContentType(..)
    , ContentInfo(..)
    , getContentType
    -- * Reading and writing PEM files
    , module Crypto.Store.CMS.PEM
    -- * Content encapsulation
    , Encap(..)
    , fromEncap
    , Encapsulates
    , isAttached
    , fromAttached
    , toAttachedCI
    , isDetached
    , fromDetached
    , toDetachedCI
    -- * Signed data
    , SignatureValue
    , SignatureAlg(..)
    , EncapsulatedContent
    , SignedData(..)
    , ProducerOfSI
    , ConsumerOfSI
    , signData
    , verifySignedData
    -- ** Signer information
    , SignerInfo(..)
    , SignerIdentifier(..)
    , IssuerAndSerialNumber(..)
    , certSigner
    , withPublicKey
    , withSignerKey
    , withSignerCertificate
    -- * Enveloped data
    , EncryptedKey
    , KeyEncryptionParams(..)
    , KeyTransportParams(..)
    , KeyAgreementParams(..)
    , KeyAgreementKDF(..)
    , RecipientInfo(..)
    , EnvelopedData(..)
    , ProducerOfRI
    , ConsumerOfRI
    , envelopData
    , openEnvelopedData
    -- ** Key Transport recipients
    , KTRecipientInfo(..)
    , RecipientIdentifier(..)
    , forKeyTransRecipient
    , withRecipientKeyTrans
    -- ** Key Agreement recipients
    , KARecipientInfo(..)
    , OriginatorIdentifierOrKey(..)
    , OriginatorPublicKey
    , RecipientEncryptedKey(..)
    , KeyAgreeRecipientIdentifier(..)
    , UserKeyingMaterial
    , forKeyAgreeRecipient
    , withRecipientKeyAgree
    -- ** Key Encryption Key recipients
    , KEKRecipientInfo(..)
    , KeyIdentifier(..)
    , OtherKeyAttribute(..)
    , KeyEncryptionKey
    , forKeyRecipient
    , withRecipientKey
     -- ** Password recipients
    , PasswordRecipientInfo(..)
    , forPasswordRecipient
    , withRecipientPassword
    -- * Digested data
    , DigestProxy(..)
    , DigestAlgorithm(..)
    , DigestedData(..)
    , digestData
    , digestVerify
    -- * Encrypted data
    , ContentEncryptionKey
    , ContentEncryptionCipher(..)
    , ContentEncryptionAlg(..)
    , ContentEncryptionParams
    , EncryptedContent
    , EncryptedData(..)
    , generateEncryptionParams
    , generateRC2EncryptionParams
    , getContentEncryptionAlg
    , encryptData
    , decryptData
    -- * Authenticated data
    , AuthenticationKey
    , MACAlgorithm(..)
    , MessageAuthenticationCode
    , AuthenticatedData(..)
    , generateAuthenticatedData
    , verifyAuthenticatedData
    -- * Authenticated-enveloped data
    , AuthContentEncryptionAlg(..)
    , AuthContentEncryptionParams
    , AuthEnvelopedData(..)
    , generateAuthEnc128Params
    , generateAuthEnc256Params
    , generateChaChaPoly1305Params
    , generateCCMParams
    , generateGCMParams
    , authEnvelopData
    , openAuthEnvelopedData
    -- * Key derivation
    , Salt
    , generateSalt
    , KeyDerivationFunc(..)
    , PBKDF2_PRF(..)
    -- * Secret-key algorithms
    , HasKeySize(..)
    , generateKey
    -- * RSA padding modes
    , MaskGenerationFunc(..)
    , OAEPParams(..)
    , PSSParams(..)
    -- * CMS attributes
    , Attribute(..)
    , findAttribute
    , setAttribute
    , filterAttributes
    -- * CMS standard attributes
    , getSigningTimeAttr
    , setSigningTimeAttr
    , setSigningTimeAttrCurrent
    -- * Originator information
    , OriginatorInfo(..)
    , CertificateChoice(..)
    , OtherCertificateFormat(..)
    , RevocationInfoChoice(..)
    , OtherRevocationInfoFormat(..)
    -- * ASN.1 representation
    , ASN1ObjectExact
    ) where

import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.ByteString (ByteString)
import Data.Maybe (isJust)
import Data.List (nub)

import Crypto.Hash

import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Attribute
import Crypto.Store.CMS.Authenticated
import Crypto.Store.CMS.AuthEnveloped
import Crypto.Store.CMS.Digested
import Crypto.Store.CMS.Encrypted
import Crypto.Store.CMS.Enveloped
import Crypto.Store.CMS.OriginatorInfo
import Crypto.Store.CMS.Info
import Crypto.Store.CMS.PEM
import Crypto.Store.CMS.Signed
import Crypto.Store.CMS.Type
import Crypto.Store.CMS.Util
import Crypto.Store.Error
import Crypto.Store.Util


-- DigestedData

-- | Add a digested-data layer on the specified content info.
digestData :: DigestAlgorithm -> ContentInfo -> DigestedData EncapsulatedContent
digestData (DigestAlgorithm alg) ci = dd
  where dd = DigestedData
                 { ddDigestAlgorithm = alg
                 , ddContentType = getContentType ci
                 , ddEncapsulatedContent = encapsulate ci
                 , ddDigest = hash (encapsulate ci)
                 }

-- | Return the inner content info but only if the digest is valid.
digestVerify :: DigestedData EncapsulatedContent -> Either StoreError ContentInfo
digestVerify DigestedData{..}
    | not acceptable = Left (InvalidParameter "Digest too weak")
    | ddDigest == hash ddEncapsulatedContent =
        decapsulate ddContentType ddEncapsulatedContent
    | otherwise = Left DigestMismatch
  where acceptable = securityAcceptable (DigestAlgorithm ddDigestAlgorithm)


-- EncryptedData

-- | Add an encrypted-data layer on the specified content info.  The content is
-- encrypted with specified key and algorithm.
--
-- Some optional attributes can be added but will not be encrypted.
encryptData :: ContentEncryptionKey
            -> ContentEncryptionParams
            -> [Attribute]
            -> ContentInfo
            -> Either StoreError (EncryptedData EncryptedContent)
encryptData key params attrs ci =
    build <$> contentEncrypt key params (encapsulate ci)
  where
    build ec = EncryptedData
                   { edContentType = getContentType ci
                   , edContentEncryptionParams = params
                   , edEncryptedContent = ec
                   , edUnprotectedAttrs = attrs
                   }

-- | Decrypt an encrypted content info using the specified key.
decryptData :: ContentEncryptionKey
            -> EncryptedData EncryptedContent
            -> Either StoreError ContentInfo
decryptData key EncryptedData{..} = do
    decrypted <- contentDecrypt key edContentEncryptionParams edEncryptedContent
    decapsulate edContentType decrypted


-- EnvelopedData

-- | Add an enveloped-data layer on the specified content info.  The content is
-- encrypted with specified key and algorithm.  The key is then processed by
-- one or several 'ProducerOfRI' functions to create recipient info elements.
--
-- Some optional attributes can be added but will not be encrypted.
envelopData :: Applicative f
            => OriginatorInfo
            -> ContentEncryptionKey
            -> ContentEncryptionParams
            -> [ProducerOfRI f]
            -> [Attribute]
            -> ContentInfo
            -> f (Either StoreError (EnvelopedData EncryptedContent))
envelopData oinfo key params envFns attrs ci =
    f <$> (sequence <$> traverse ($ key) envFns)
  where
    ebs = contentEncrypt key params (encapsulate ci)
    f ris = build <$> ebs <*> ris
    build bs ris = EnvelopedData
                       { evOriginatorInfo = oinfo
                       , evRecipientInfos = ris
                       , evContentType = getContentType ci
                       , evContentEncryptionParams = params
                       , evEncryptedContent = bs
                       , evUnprotectedAttrs = attrs
                       }

-- | Recover an enveloped content info using the specified 'ConsumerOfRI'
-- function.
openEnvelopedData :: Monad m
                  => ConsumerOfRI m
                  -> EnvelopedData EncryptedContent
                  -> m (Either StoreError ContentInfo)
openEnvelopedData devFn EnvelopedData{..} = do
    r <- riAttempts (map (fmap (>>= decr) . devFn) evRecipientInfos)
    return (r >>= decapsulate ct)
  where
    ct       = evContentType
    params   = evContentEncryptionParams
    decr k   = contentDecrypt k params evEncryptedContent


-- AuthenticatedData

-- | Key used for authentication.
type AuthenticationKey = ContentEncryptionKey

-- | Add an authenticated-data layer on the specified content info.  The content
-- is MACed with the specified key and algorithms.  The key is then processed by
-- one or several 'ProducerOfRI' functions to create recipient info elements.
--
-- Two lists of optional attributes can be provided.  The attributes will be
-- part of message authentication when provided in the first list.
generateAuthenticatedData :: Applicative f
                          => OriginatorInfo
                          -> AuthenticationKey
                          -> MACAlgorithm
                          -> Maybe DigestAlgorithm
                          -> [ProducerOfRI f]
                          -> [Attribute]
                          -> [Attribute]
                          -> ContentInfo
                          -> f (Either StoreError (AuthenticatedData EncapsulatedContent))
generateAuthenticatedData oinfo key macAlg digAlg envFns aAttrs uAttrs ci =
    f <$> (sequence <$> traverse ($ key) envFns)
  where
    msg = encapsulate ci
    ct  = getContentType ci

    (aAttrs', input) =
        case digAlg of
            Nothing  -> (aAttrs, msg)
            Just dig ->
                let md = digest dig msg
                    l  = setContentTypeAttr ct $ setMessageDigestAttr md aAttrs
                in (l, encodeAuthAttrs l)

    ebs   = mac macAlg key input
    f ris = build ebs <$> ris
    build authTag ris = AuthenticatedData
                            { adOriginatorInfo = oinfo
                            , adRecipientInfos = ris
                            , adMACAlgorithm = macAlg
                            , adDigestAlgorithm = digAlg
                            , adContentType = getContentType ci
                            , adEncapsulatedContent = encapsulate ci
                            , adAuthAttrs = aAttrs'
                            , adMAC = authTag
                            , adUnauthAttrs = uAttrs
                            }

-- | Verify the integrity of an authenticated content info using the specified
-- 'ConsumerOfRI' function.  The inner content info is returned only if the MAC
-- could be verified.
verifyAuthenticatedData :: Monad m
                        => ConsumerOfRI m
                        -> AuthenticatedData EncapsulatedContent
                        -> m (Either StoreError ContentInfo)
verifyAuthenticatedData devFn AuthenticatedData{..} =
    riAttempts (map (fmap (>>= unwrap) . devFn) adRecipientInfos)
  where
    msg = adEncapsulatedContent
    ct  = adContentType

    noAttr    = null adAuthAttrs
    mdMatch   = case adDigestAlgorithm of
                    Nothing  -> False
                    Just dig -> mdAttr == Just (digest dig msg)
    mdAccept  = maybe True securityAcceptable adDigestAlgorithm
    macAccept = securityAcceptable adMACAlgorithm
    attrMatch = ctAttr == Just ct && mdMatch
    mdAttr    = getMessageDigestAttr adAuthAttrs
    ctAttr    = getContentTypeAttr adAuthAttrs
    input     = if noAttr then msg else encodeAuthAttrs adAuthAttrs

    unwrap k
        | isJust adDigestAlgorithm && noAttr  = Left (InvalidInput "Missing auth attributes")
        | not noAttr && not attrMatch         = Left (InvalidInput "Invalid auth attributes")
        | not mdAccept                        = Left (InvalidParameter "Digest too weak")
        | not macAccept                       = Left (InvalidParameter "MAC too weak")
        | adMAC /= mac adMACAlgorithm k input = Left BadContentMAC
        | otherwise                           = decapsulate adContentType adEncapsulatedContent


-- AuthEnvelopedData

-- | Add an authenticated-enveloped-data layer on the specified content info.
-- The content is encrypted with specified key and algorithm.  The key is then
-- processed by one or several 'ProducerOfRI' functions to create recipient info
-- elements.
--
-- Some attributes can be added but will not be encrypted.  The attributes
-- will be part of message authentication when provided in the first list.
authEnvelopData :: Applicative f
                => OriginatorInfo
                -> ContentEncryptionKey
                -> AuthContentEncryptionParams
                -> [ProducerOfRI f]
                -> [Attribute]
                -> [Attribute]
                -> ContentInfo
                -> f (Either StoreError (AuthEnvelopedData EncryptedContent))
authEnvelopData oinfo key params envFns aAttrs uAttrs ci =
    f <$> (sequence <$> traverse ($ key) envFns)
  where
    raw = encodeASN1Object params
    aad = encodeAuthAttrs aAttrs
    ebs = authContentEncrypt key params raw aad (encapsulate ci)
    f ris = build <$> ebs <*> ris
    build (authTag, bs) ris = AuthEnvelopedData
                       { aeOriginatorInfo = oinfo
                       , aeRecipientInfos = ris
                       , aeContentType = getContentType ci
                       , aeContentEncryptionParams = ASN1ObjectExact params raw
                       , aeEncryptedContent = bs
                       , aeAuthAttrs = aAttrs
                       , aeMAC = authTag
                       , aeUnauthAttrs = uAttrs
                       }

-- | Recover an authenticated-enveloped content info using the specified
-- 'ConsumerOfRI' function.
openAuthEnvelopedData :: Monad m
                      => ConsumerOfRI m
                      -> AuthEnvelopedData EncryptedContent
                      -> m (Either StoreError ContentInfo)
openAuthEnvelopedData devFn AuthEnvelopedData{..} = do
    r <- riAttempts (map (fmap (>>= decr) . devFn) aeRecipientInfos)
    return (r >>= decapsulate ct)
  where
    ct       = aeContentType
    params   = exactObject aeContentEncryptionParams
    raw      = exactObjectRaw aeContentEncryptionParams
    aad      = encodeAuthAttrs aeAuthAttrs
    decr k   = authContentDecrypt k params raw aad aeEncryptedContent aeMAC


-- SignedData

-- | Add a signed-data layer on the specified content info.  The content is
-- processed by one or several 'ProducerOfSI' functions to create signer info
-- elements.
signData :: Applicative f
         => [ProducerOfSI f] -> ContentInfo -> f (Either StoreError (SignedData EncapsulatedContent))
signData sigFns ci =
    f <$> (sequence <$> traverse (\fn -> fn ct msg) sigFns)
  where
    msg = encapsulate ci
    ct  = getContentType ci
    f   = fmap (build . unzip3)

    build (sis, certLists, crlLists) =
        SignedData
            { sdDigestAlgorithms = nub (map siDigestAlgorithm sis)
            , sdContentType = getContentType ci
            , sdEncapsulatedContent = encapsulate ci
            , sdCertificates = concat certLists
            , sdCRLs = concat crlLists
            , sdSignerInfos = sis
            }

-- | Verify a signed content info using the specified 'ConsumerOfSI' function.
-- Verification of at least one signer info must be successful in order to
-- return the inner content info.
verifySignedData :: Monad m
                 => ConsumerOfSI m -> SignedData EncapsulatedContent -> m (Either StoreError ContentInfo)
verifySignedData verFn SignedData{..} =
    f <$> siAttemps valid sdSignerInfos
  where
    msg      = sdEncapsulatedContent
    ct       = sdContentType
    valid si = verFn ct msg si sdCertificates sdCRLs
    f bool   = if bool then decapsulate sdContentType sdEncapsulatedContent
                       else Left SignatureNotVerified


-- Utilities

riAttempts :: Monad m => [m (Either StoreError b)] -> m (Either StoreError b)
riAttempts []       = return (Left NoRecipientInfoFound)
riAttempts [single] = single
riAttempts list     = loop list
  where
    loop []     = return (Left NoRecipientInfoMatched)
    loop (x:xs) = x >>= orTail xs

    orTail xs (Left _)  = loop xs
    orTail _  success   = return success

siAttemps :: Monad m => (a -> m Bool) -> [a] -> m Bool
siAttemps _ []     = pure False
siAttemps f (x:xs) = f x >>= orTail
  where orTail bool = if bool then return True else siAttemps f xs

decode :: ParseASN1 [ASN1Event] a -> ByteString -> Either StoreError a
decode parser bs = vals >>= mapLeft ParseFailure . runParseASN1_ parser
  where vals = mapLeft DecodingError (decodeASN1Repr' BER bs)

-- | Encode the information for encapsulation in another content info.
encapsulate :: ContentInfo -> ByteString
encapsulate (DataCI bs)              = bs
encapsulate (SignedDataCI ed)        = encodeASN1Object ed
encapsulate (EnvelopedDataCI ed)     = encodeASN1Object ed
encapsulate (DigestedDataCI dd)      = encodeASN1Object dd
encapsulate (EncryptedDataCI ed)     = encodeASN1Object ed
encapsulate (AuthenticatedDataCI ad) = encodeASN1Object ad
encapsulate (AuthEnvelopedDataCI ae) = encodeASN1Object ae

-- | Decode the information from encapsulated content.
decapsulate :: ContentType -> ByteString -> Either StoreError ContentInfo
decapsulate DataType bs              = pure (DataCI bs)
decapsulate SignedDataType bs        = SignedDataCI <$> decode parse bs
decapsulate EnvelopedDataType bs     = EnvelopedDataCI <$> decode parse bs
decapsulate DigestedDataType bs      = DigestedDataCI <$> decode parse bs
decapsulate EncryptedDataType bs     = EncryptedDataCI <$> decode parse bs
decapsulate AuthenticatedDataType bs = AuthenticatedDataCI <$> decode parse bs
decapsulate AuthEnvelopedDataType bs = AuthEnvelopedDataCI <$> decode parse bs
