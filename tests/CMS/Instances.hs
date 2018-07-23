{-# OPTIONS_GHC -fno-warn-orphans #-}
-- | Orphan instances.
module CMS.Instances
    ( arbitraryPassword
    , arbitraryAttributes
    , arbitraryKeyPair
    , arbitrarySigVer
    , arbitraryEnvDev
    ) where

import           Data.ASN1.Types
import qualified Data.ByteArray as B
import           Data.ByteString (ByteString)
import           Data.X509

import Test.Tasty.QuickCheck

import Crypto.Cipher.Types

import Crypto.Store.CMS

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
                       , arbitrarySignedData
                       , arbitraryEnvelopedData
                       , arbitraryDigestedData
                       , arbitraryEncryptedData
                       , arbitraryAuthenticatedData
                       , arbitraryAuthEnvelopedData
                       ]
      where
        arbitraryMessage :: Gen ByteString
        arbitraryMessage = resize 2048 (B.pack <$> arbitrary)

        arbitrarySignedData :: Gen ContentInfo
        arbitrarySignedData = do
            alg   <- arbitrary
            (sigFns, _) <- arbitrarySigVer alg
            inner <- scale (subtract $ length sigFns) arbitrary
            signData sigFns inner >>= either fail return

        arbitraryEnvelopedData :: Gen ContentInfo
        arbitraryEnvelopedData = do
            oinfo <- arbitrary
            (alg, key, attrs) <- getCommon
            (envFns, _) <- arbitraryEnvDev key
            inner <- scale (subtract $ length envFns) arbitrary
            envelopData oinfo key alg envFns attrs inner >>= either fail return

        arbitraryDigestedData :: Gen ContentInfo
        arbitraryDigestedData = do
            inner <- scale pred arbitrary
            dt <- arbitrary
            return $ digestData dt inner

        arbitraryEncryptedData :: Gen ContentInfo
        arbitraryEncryptedData = do
            (alg, key, attrs) <- getCommon
            inner <- scale pred arbitrary
            either fail return $ encryptData key alg attrs inner

        arbitraryAuthenticatedData :: Gen ContentInfo
        arbitraryAuthenticatedData = do
            (oinfo, alg, key, envFns, aAttrs, uAttrs) <- getCommonAuth
            dig <- arbitrary
            inner <- scale (subtract $ length envFns) arbitrary
            generateAuthenticatedData oinfo key alg dig envFns aAttrs uAttrs inner
                >>= either fail return

        arbitraryAuthEnvelopedData :: Gen ContentInfo
        arbitraryAuthEnvelopedData = do
            (oinfo, alg, key, envFns, aAttrs, uAttrs) <- getCommonAuth
            inner <- scale (subtract $ length envFns) arbitrary
            authEnvelopData oinfo key alg envFns aAttrs uAttrs inner
                >>= either fail return

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

instance Arbitrary Attribute where
    arbitrary = do
        oid  <- arbitraryOID
        vals <- resize 3 $ listOf1 (OctetString <$> arbitrarySmall)
        return Attribute { attrType = oid, attrValues = vals }

arbitraryAttributes :: Gen [Attribute]
arbitraryAttributes = resize 3 arbitrary

instance Arbitrary DigestType where
    arbitrary = elements
        [ DigestType MD5
        , DigestType SHA1
        , DigestType SHA224
        , DigestType SHA256
        , DigestType SHA384
        , DigestType SHA512
        ]

instance Arbitrary MACAlgorithm where
    arbitrary = (\(DigestType alg) -> HMAC alg) <$> arbitrary

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

        , pure $ RSA (DigestType MD2)
        , pure $ RSA (DigestType MD5)
        , pure $ RSA (DigestType SHA1)
        , pure $ RSA (DigestType SHA224)
        , pure $ RSA (DigestType SHA256)
        , pure $ RSA (DigestType SHA384)
        , pure $ RSA (DigestType SHA512)

        , RSAPSS <$> arbitrary

        , pure $ DSA (DigestType SHA1)
        , pure $ DSA (DigestType SHA224)
        , pure $ DSA (DigestType SHA256)

        , pure $ ECDSA (DigestType SHA1)
        , pure $ ECDSA (DigestType SHA224)
        , pure $ ECDSA (DigestType SHA256)
        , pure $ ECDSA (DigestType SHA384)
        , pure $ ECDSA (DigestType SHA512)
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

arbitrarySigVer :: SignatureAlg -> Gen ([ProducerOfSI Gen], ConsumerOfSI)
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
    arbitrary = arbitrary >>= generateEncryptionParams

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

arbitraryAgreeParams :: KeyEncryptionParams -> Gen KeyAgreementParams
arbitraryAgreeParams alg = oneof
    [ flip StdDH alg <$> arbitraryDigest
    , flip CofactorDH alg <$> arbitraryDigest
    ]
  where
    arbitraryDigest =
        elements
            [ DigestType SHA1
            , DigestType SHA224
            , DigestType SHA256
            , DigestType SHA384
            , DigestType SHA512
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
        (pub, priv) <- arbitraryNamedEC
        cert <- arbitrarySignedCertificate (PubKeyEC pub)
        kap  <- arbitraryAlg >>= arbitraryAgreeParams
        let envFn = forKeyAgreeRecipient cert kap
            devFn = withRecipientKeyAgree (PrivKeyEC priv) cert
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
                                 ]
        | mod len 8 == 0 = oneof [ return AES128_WRAP
                                 , return AES192_WRAP
                                 , return AES256_WRAP
                                 , return AES128_WRAP_PAD
                                 , return AES192_WRAP_PAD
                                 , return AES256_WRAP_PAD
                                 ]
        | otherwise      = oneof [ return AES128_WRAP_PAD
                                 , return AES192_WRAP_PAD
                                 , return AES256_WRAP_PAD
                                 ]

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
