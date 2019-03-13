{-# LANGUAGE DataKinds #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
-- | Orphan instances.
module CMS.Instances
    ( arbitraryPassword
    , arbitraryAttributes
    , arbitraryIntegrityDigest
    , arbitrarySigVer
    , arbitraryEnvDev
    ) where

import           Data.ASN1.Types
import qualified Data.ByteArray as B
import           Data.ByteString (ByteString)
import           Data.Proxy
import           Data.X509

import Test.Tasty.QuickCheck

import Crypto.Cipher.Types

import Crypto.Store.CMS
import Crypto.Store.Error

import X509.Instances

arbitrarySmall :: Gen ByteString
arbitrarySmall = resize 10 (B.pack <$> arbitrary)

arbitraryPassword :: Gen ByteString
arbitraryPassword = resize 16 (B.pack <$> asciiChar)
  where asciiChar = listOf $ choose (0x20,0x7f)

instance Arbitrary ContentInfo where
    arbitrary = sized $ \n ->
        if n == 0
            then DataCI <$> arbitraryMessage
            else oneof [ DataCI <$> arbitraryMessage
                       , SignedDataCI <$> arbitrarySignedData
                       , EnvelopedDataCI <$> arbitraryEnvelopedData
                       , DigestedDataCI <$> arbitraryDigestedData
                       , EncryptedDataCI <$> arbitraryEncryptedData
                       , AuthenticatedDataCI <$> arbitraryAuthenticatedData
                       , AuthEnvelopedDataCI <$> arbitraryAuthEnvelopedData
                       ]
      where
        arbitraryMessage :: Gen ByteString
        arbitraryMessage = resize 2048 (B.pack <$> arbitrary)

        arbitrarySignedData :: Gen SignedData
        arbitrarySignedData = do
            alg   <- arbitrary
            (sigFns, _) <- arbitrarySigVer alg
            inner <- scale (subtract $ length sigFns) arbitrary
            signData sigFns inner >>= failIfError

        arbitraryEnvelopedData :: Gen (EnvelopedData EncryptedContent)
        arbitraryEnvelopedData = do
            oinfo <- arbitrary
            (alg, key, attrs) <- getCommon
            (envFns, _) <- arbitraryEnvDev key
            inner <- scale (subtract $ length envFns) arbitrary
            envelopData oinfo key alg envFns attrs inner >>= failIfError

        arbitraryDigestedData :: Gen DigestedData
        arbitraryDigestedData = do
            inner <- scale pred arbitrary
            dt <- arbitrary
            return $ digestData dt inner

        arbitraryEncryptedData :: Gen (EncryptedData EncryptedContent)
        arbitraryEncryptedData = do
            (alg, key, attrs) <- getCommon
            inner <- scale pred arbitrary
            failIfError $ encryptData key alg attrs inner

        arbitraryAuthenticatedData :: Gen AuthenticatedData
        arbitraryAuthenticatedData = do
            (oinfo, alg, key, envFns, aAttrs, uAttrs) <- getCommonAuth
            dig <- arbitrary
            inner <- scale (subtract $ length envFns) arbitrary
            generateAuthenticatedData oinfo key alg dig envFns aAttrs uAttrs inner
                >>= failIfError

        arbitraryAuthEnvelopedData :: Gen (AuthEnvelopedData EncryptedContent)
        arbitraryAuthEnvelopedData = do
            (oinfo, alg, key, envFns, aAttrs, uAttrs) <- getCommonAuth
            inner <- scale (subtract $ length envFns) arbitrary
            authEnvelopData oinfo key alg envFns aAttrs uAttrs inner
                >>= failIfError

        getCommonAuth :: (HasKeySize params, Arbitrary params)
                  => Gen ( OriginatorInfo, params, ContentEncryptionKey
                         , [ProducerOfRI Gen], [Attribute], [Attribute]
                         )
        getCommonAuth = do
            oinfo <- arbitrary
            (alg, key, uAttrs) <- getCommon
            aAttrs <- arbitraryAttributes
            (envFns, _) <- arbitraryEnvDev key
            return (oinfo, alg, key, envFns, aAttrs, uAttrs)

        getCommon :: (HasKeySize params, Arbitrary params, B.ByteArray key)
                  => Gen (params, key, [Attribute])
        getCommon = do
            alg   <- arbitrary
            key   <- generateKey alg
            attrs <- arbitraryAttributes
            return (alg, key, attrs)

        failIfError :: Either StoreError a -> Gen a
        failIfError = either (fail . show) return

instance Arbitrary Attribute where
    arbitrary = do
        oid  <- arbitraryOID
        vals <- resize 3 $ listOf1 (OctetString <$> arbitrarySmall)
        return Attribute { attrType = oid, attrValues = vals }

arbitraryAttributes :: Gen [Attribute]
arbitraryAttributes = resize 3 arbitrary

p256 :: Proxy 256
p256 = Proxy

p512 :: Proxy 512
p512 = Proxy

instance Arbitrary DigestAlgorithm where
    arbitrary = oneof
        [ pure $ DigestAlgorithm MD2
        , pure $ DigestAlgorithm MD4
        , pure $ DigestAlgorithm MD5
        , pure $ DigestAlgorithm SHA1
        , pure $ DigestAlgorithm SHA224
        , pure $ DigestAlgorithm SHA256
        , pure $ DigestAlgorithm SHA384
        , pure $ DigestAlgorithm SHA512
        , pure $ DigestAlgorithm SHAKE128_256
        , pure $ DigestAlgorithm SHAKE256_512
        , pure $ DigestAlgorithm (SHAKE128 p256)
        , pure $ DigestAlgorithm (SHAKE256 p512)
        ]

arbitraryIntegrityDigest :: Gen DigestAlgorithm
arbitraryIntegrityDigest = elements
    [ DigestAlgorithm MD5
    , DigestAlgorithm SHA1
    , DigestAlgorithm SHA224
    , DigestAlgorithm SHA256
    , DigestAlgorithm SHA384
    , DigestAlgorithm SHA512
    ]

instance Arbitrary MACAlgorithm where
    arbitrary = (\(DigestAlgorithm alg) -> HMAC alg) <$> arbitraryIntegrityDigest

instance Arbitrary OAEPParams where
    arbitrary = do
        alg <- arbitrary
        mga <- MGF1 <$> arbitrary
        return OAEPParams { oaepHashAlgorithm = alg
                          , oaepMaskGenAlgorithm = mga
                          }

instance Arbitrary PSSParams where
    arbitrary = do
        alg <- arbitrary
        mga <- MGF1 <$> arbitrary
        len <- choose (1, 30)
        return PSSParams { pssHashAlgorithm = alg
                         , pssMaskGenAlgorithm = mga
                         , pssSaltLength = len
                         }

instance Arbitrary SignatureAlg where
    arbitrary = oneof
        [ pure RSAAnyHash

        , pure $ RSA (DigestAlgorithm MD2)
        , pure $ RSA (DigestAlgorithm MD5)
        , pure $ RSA (DigestAlgorithm SHA1)
        , pure $ RSA (DigestAlgorithm SHA224)
        , pure $ RSA (DigestAlgorithm SHA256)
        , pure $ RSA (DigestAlgorithm SHA384)
        , pure $ RSA (DigestAlgorithm SHA512)

        , RSAPSS <$> arbitrary

        , pure $ DSA (DigestAlgorithm SHA1)
        , pure $ DSA (DigestAlgorithm SHA224)
        , pure $ DSA (DigestAlgorithm SHA256)

        , pure $ ECDSA (DigestAlgorithm SHA1)
        , pure $ ECDSA (DigestAlgorithm SHA224)
        , pure $ ECDSA (DigestAlgorithm SHA256)
        , pure $ ECDSA (DigestAlgorithm SHA384)
        , pure $ ECDSA (DigestAlgorithm SHA512)

        , pure Ed25519
        , pure Ed448
        ]

arbitraryKeyPair :: SignatureAlg -> Gen (PubKey, PrivKey)
arbitraryKeyPair RSAAnyHash = do
    (pub, priv) <- arbitraryRSA
    return (PubKeyRSA pub, PrivKeyRSA priv)
arbitraryKeyPair (RSA _) = do
    (pub, priv) <- arbitraryRSA
    return (PubKeyRSA pub, PrivKeyRSA priv)
arbitraryKeyPair (RSAPSS _) = do
    (pub, priv) <- arbitraryRSA
    return (PubKeyRSA pub, PrivKeyRSA priv)
arbitraryKeyPair (DSA _) = do
    (pub, priv) <- arbitraryDSA
    return (PubKeyDSA pub, PrivKeyDSA priv)
arbitraryKeyPair (ECDSA _) = do
    (pub, priv) <- arbitraryNamedEC
    return (PubKeyEC pub, PrivKeyEC priv)
arbitraryKeyPair Ed25519 = do
    (pub, priv) <- arbitraryEd25519
    return (PubKeyEd25519 pub, PrivKeyEd25519 priv)
arbitraryKeyPair Ed448 = do
    (pub, priv) <- arbitraryEd448
    return (PubKeyEd448 pub, PrivKeyEd448 priv)

arbitrarySigVer :: SignatureAlg -> Gen ([ProducerOfSI Gen], ConsumerOfSI Gen)
arbitrarySigVer alg = sized $ \n -> do
    (sigFn, verFn) <- onePair
    otherPairs <- resize (min (pred n) 3) $ listOf onePair
    sigFns <- shuffle (sigFn : map fst otherPairs)
    return (sigFns, verFn)
  where
    onePair = do
        (pub, priv) <- arbitraryKeyPair alg
        chain <- arbitraryCertificateChain pub
        sAttrs <- oneof [ pure Nothing, Just <$> arbitraryAttributes ]
        uAttrs <- arbitraryAttributes
        return (certSigner alg priv chain sAttrs uAttrs, withPublicKey pub)

instance Arbitrary PBKDF2_PRF where
    arbitrary = elements
        [ PBKDF2_SHA1
        , PBKDF2_SHA256
        , PBKDF2_SHA512
        ]

instance Arbitrary ContentEncryptionAlg where
    arbitrary = elements
        [ CBC DES
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

instance Arbitrary ContentEncryptionParams where
    arbitrary = arbitrary >>= gen
      where
        gen CBC_RC2 = choose (24, 512) >>= generateRC2EncryptionParams
        gen alg     = generateEncryptionParams alg

instance Arbitrary AuthContentEncryptionAlg where
    arbitrary = elements
        [ AUTH_ENC_128
        , AUTH_ENC_256
        , CHACHA20_POLY1305

        , CCM AES128
        , CCM AES192
        , CCM AES256

        , GCM AES128
        , GCM AES192
        , GCM AES256
        ]

instance Arbitrary AuthContentEncryptionParams where
    arbitrary = do
        alg <- arbitrary
        case alg of
            AUTH_ENC_128 -> arb3 generateAuthEnc128Params
            AUTH_ENC_256 -> arb3 generateAuthEnc256Params
            CHACHA20_POLY1305 -> generateChaChaPoly1305Params
            CCM c -> do m <- arbitraryM
                        l <- arbitraryL
                        generateCCMParams c m l
            GCM c -> choose (12,16) >>= generateGCMParams c
      where arb3 fn = do
                a <- arbitrary; b <- arbitrary; c <- arbitrary
                fn a b c

arbitraryM :: Gen CCM_M
arbitraryM = elements
    [ CCM_M4
    , CCM_M6
    , CCM_M8
    , CCM_M10
    , CCM_M12
    , CCM_M14
    , CCM_M16
    ]

arbitraryL :: Gen CCM_L
arbitraryL = elements [ CCM_L2, CCM_L3, CCM_L4 ]

instance Arbitrary KeyDerivationFunc where
    arbitrary = do
        salt <- generateSalt 8
        oneof [ pbkdf2 salt , scrypt salt ]
      where
        pbkdf2 salt = do
            iters <- choose (1,512)
            pf <- arbitrary
            return PBKDF2 { pbkdf2Salt           = salt
                          , pbkdf2IterationCount = iters
                          , pbkdf2KeyLength      = Nothing
                          , pbkdf2Prf            = pf
                          }
        scrypt salt = do
            (n, r, p) <- elements [ (16, 1, 1) , (1024, 8, 16) ]
            return Scrypt { scryptSalt      = salt
                          , scryptN         = n
                          , scryptR         = r
                          , scryptP         = p
                          , scryptKeyLength = Nothing
                          }

instance Arbitrary KeyTransportParams where
    arbitrary = oneof
        [ pure RSAES
        , RSAESOAEP <$> arbitrary
        ]

instance Arbitrary KeyEncryptionParams where
    arbitrary = oneof
        [ PWRIKEK <$> arbitrary
        , return AES128_WRAP
        , return AES192_WRAP
        , return AES256_WRAP
        , return AES128_WRAP_PAD
        , return AES192_WRAP_PAD
        , return AES256_WRAP_PAD
        , return DES_EDE3_WRAP
        , RC2_WRAP <$> choose (1, 1024)
        ]

instance Arbitrary OtherKeyAttribute where
    arbitrary = do
        oid <- arbitraryOID
        vals <- resize 3 $ listOf1 (OctetString <$> arbitrarySmall)
        return OtherKeyAttribute { keyAttrId = oid, keyAttr = vals }

instance Arbitrary KeyIdentifier where
    arbitrary = do
        kid <- arbitrarySmall
        KeyIdentifier kid Nothing <$> arbitrary

arbitraryAgreeParams :: Bool -> KeyEncryptionParams -> Gen KeyAgreementParams
arbitraryAgreeParams allowCofactorDH alg
    | allowCofactorDH = oneof
        [ flip StdDH alg <$> arbitraryDigest
        , flip CofactorDH alg <$> arbitraryDigest
        ]
    | otherwise = flip StdDH alg <$> arbitraryDigest
  where
    arbitraryDigest =
        elements
            [ DigestAlgorithm SHA1
            , DigestAlgorithm SHA224
            , DigestAlgorithm SHA256
            , DigestAlgorithm SHA384
            , DigestAlgorithm SHA512
            ]

arbitraryEnvDev :: ContentEncryptionKey
                -> Gen ([ProducerOfRI Gen], ConsumerOfRI Gen)
arbitraryEnvDev cek = sized $ \n -> do
    (envFn, devFn) <- onePair
    otherPairs <- resize (min (pred n) 3) $ listOf onePair
    envFns <- shuffle (envFn : map fst otherPairs)
    return (envFns, devFn)
  where
    len     = B.length cek
    onePair = oneof [ arbitraryKT, arbitraryKA, arbitraryKEK, arbitraryPW ]

    arbitraryKT = do
        (pub, priv) <- arbitraryLargeRSA
        cert <- arbitrarySignedCertificate (PubKeyRSA pub)
        ktp  <- arbitrary
        let envFn = forKeyTransRecipient cert ktp
            devFn = withRecipientKeyTrans (PrivKeyRSA priv)
        return (envFn, devFn)

    arbitraryKA = do
        (cert, priv) <- arbitraryDHParams
        let allowCofactorDH =
                case priv of
                    PrivKeyEC _ -> True
                    _           -> False
        kap <- arbitraryAlg >>= arbitraryAgreeParams allowCofactorDH
        let envFn = forKeyAgreeRecipient cert kap
            devFn = withRecipientKeyAgree priv cert
        return (envFn, devFn)

    arbitraryKEK = do
        kid <- arbitrary
        es  <- arbitraryAlg
        key <- generateKey es
        return (forKeyRecipient key kid es, withRecipientKey key)

    arbitraryPW  = do
        pwd <- arbitraryPassword
        kdf <- arbitrary
        cea <- arbitrary `suchThat` notModeCTR
        let es = PWRIKEK cea
        return (forPasswordRecipient pwd kdf es, withRecipientPassword pwd)

    arbitraryAlg
        | len == 24      = oneof [ return AES128_WRAP
                                 , return AES192_WRAP
                                 , return AES256_WRAP
                                 , return AES128_WRAP_PAD
                                 , return AES192_WRAP_PAD
                                 , return AES256_WRAP_PAD
                                 , return DES_EDE3_WRAP
                                 , RC2_WRAP <$> choose (1, 1024)
                                 ]
        | mod len 8 == 0 = oneof [ return AES128_WRAP
                                 , return AES192_WRAP
                                 , return AES256_WRAP
                                 , return AES128_WRAP_PAD
                                 , return AES192_WRAP_PAD
                                 , return AES256_WRAP_PAD
                                 , RC2_WRAP <$> choose (1, 1024)
                                 ]
        | otherwise      = oneof [ return AES128_WRAP_PAD
                                 , return AES192_WRAP_PAD
                                 , return AES256_WRAP_PAD
                                 , RC2_WRAP <$> choose (1, 1024)
                                 ]

    arbitraryDHParams = oneof [ arbitraryCredNamedEC
                              , arbitraryCredX25519
                              , arbitraryCredX448
                              ]

    arbitraryCredNamedEC = do
        (pub, priv) <- arbitraryNamedEC
        cert <- arbitrarySignedCertificate (PubKeyEC pub)
        return (cert, PrivKeyEC priv)

    arbitraryCredX25519 = do
        (pub, priv) <- arbitraryX25519
        cert <- arbitrarySignedCertificate (PubKeyX25519 pub)
        return (cert, PrivKeyX25519 priv)

    arbitraryCredX448 = do
        (pub, priv) <- arbitraryX448
        cert <- arbitrarySignedCertificate (PubKeyX448 pub)
        return (cert, PrivKeyX448 priv)

    -- key wrapping in PWRIKEK is incompatible with CTR mode so we must never
    -- generate this combination
    notModeCTR params =
        case getContentEncryptionAlg params of
            CTR _ -> False
            _     -> True

instance Arbitrary OriginatorInfo where
    arbitrary = OriginatorInfo <$> arbitrary <*> arbitrary

instance Arbitrary CertificateChoice where
    arbitrary = oneof [ CertificateCertificate <$> arbitrary
                      , CertificateOther <$> arbitrary
                      ]

instance Arbitrary RevocationInfoChoice where
    arbitrary = oneof [ RevocationInfoCRL <$> arbitrary
                      , RevocationInfoOther <$> arbitrary
                      ]

instance Arbitrary OtherCertificateFormat where
    arbitrary = do
        oid  <- arbitraryOID
        vals <- resize 3 $ listOf1 (OctetString <$> arbitrarySmall)
        return OtherCertificateFormat { otherCertFormat = oid
                                      , otherCertValues = vals
                                      }

instance Arbitrary OtherRevocationInfoFormat where
    arbitrary = do
        oid  <- arbitraryOID
        vals <- resize 3 $ listOf1 (OctetString <$> arbitrarySmall)
        return OtherRevocationInfoFormat { otherRevInfoFormat = oid
                                         , otherRevInfoValues = vals
                                         }
