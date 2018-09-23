{-# OPTIONS_GHC -fno-warn-orphans #-}
-- | Orphan instances.
module X509.Instances
    ( arbitraryOID
    , arbitraryRSA
    , arbitraryLargeRSA
    , arbitraryDSA
    , arbitraryNamedEC
    , arbitrarySignedCertificate
    , arbitraryCertificateChain
    ) where

import           Data.ASN1.Types
import qualified Data.ByteArray as B
import           Data.Hourglass
import           Data.X509

import Test.Tasty.QuickCheck

import           Crypto.Number.Serialize (i2ospOf_)
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Generate as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.RSA as RSA
import           Crypto.Random

-- Warning: not a cryptographic implementation, used for tests only
instance MonadRandom Gen where
    getRandomBytes n = B.pack <$> vector n

arbitraryOID :: Gen [Integer]
arbitraryOID = do
    o1 <- choose (0,6)
    o2 <- choose (0,15)
    os <- resize 5 $ listOf (getPositive <$> arbitrary)
    return (o1 : o2 : os)

arbitraryDN :: Gen DistinguishedName
arbitraryDN = DistinguishedName <$> resize 5 (listOf1 arbitraryDE)
  where
    arbitrarySE = elements [IA5, UTF8]
    arbitraryDE = (,) <$> arbitraryOID <*> arbitraryCS
    arbitraryCS = ASN1CharacterString <$> arbitrarySE <*> arbitraryBS
    arbitraryBS = resize 16 (B.pack <$> listOf1 arbitrary)

instance Arbitrary PubKey where
    arbitrary = oneof [ PubKeyRSA . fst <$> arbitraryRSA
                      , PubKeyDSA . fst <$> arbitraryDSA
                      , PubKeyEC . fst  <$> arbitraryNamedEC
                      --, PubKeyEC . fst  <$> arbitraryExplicitPrimeCurve
                      ]

instance Arbitrary PrivKey where
    arbitrary = oneof [ PrivKeyRSA . snd <$> arbitraryRSA
                      , PrivKeyDSA . snd <$> arbitraryDSA
                      , PrivKeyEC . snd  <$> arbitraryNamedEC
                      , PrivKeyEC . snd  <$> arbitraryExplicitPrimeCurve
                      ]

arbitraryRSA :: Gen (RSA.PublicKey, RSA.PrivateKey)
arbitraryRSA = do
    n <- elements [ 768, 1024 ]     -- enough bits to sign with SHA-512
    e <- elements [ 3, 0x10001 ]
    RSA.generate (n `div` 8) e

arbitraryLargeRSA :: Gen (RSA.PublicKey, RSA.PrivateKey)
arbitraryLargeRSA = do
    n <- elements [ 1792, 2048 ]    -- enough bits for RSA-OAEP with SHA-512
    e <- elements [ 3, 0x10001 ]
    RSA.generate (n `div` 8) e

arbitraryDSA :: Gen (DSA.PublicKey, DSA.PrivateKey)
arbitraryDSA = do
    x <- DSA.generatePrivate params
    let y = DSA.calculatePublic params x
        priv = DSA.PrivateKey { DSA.private_params = params, DSA.private_x = x }
        pub = DSA.PublicKey { DSA.public_params = params, DSA.public_y = y }
    return (pub, priv)
  where
    -- DSA parameters were generated using 'openssl dsaparam -C 2048'
    params = DSA.Params
        { DSA.params_p = 0x9994B9B1FC22EC3A5F607B5130D314F35FC8D387015A6D8FA2B56D3CC1F13FE330A631DBC765CEFFD6986BDEB8512580BBAD93D56EE7A8997DB9C65C29313FBC5077DB6F1E9D9E6D3499F997F09C8CF8ECC9E5F38DC34C3D656CFDF463893DDF9E246E223D7E5C4E86F54426DDA5DE112FCEDBFB5B6D6F7C76ED190EA1A7761CA561E8E5803F9D616DAFF25E2CCD4011A6D78D5CE8ED28CC2D865C7EC01508BA96FBD1F8BB5E517B6A5208A90AC2D3DCAE50281C02510B86C16D449465CD4B3754FD91AA19031282122A25C68292F033091FCB9DEBDE0D220F81F7EE4AB6581D24BE48204AF3DA52BDB944DA53B76148055395B30954735DC911574D360C953B
        , DSA.params_g = 0x10E51AEA37880C5E52DD477ED599D55050C47012D038B9E4B3199C9DE9A5B873B1ABC8B954F26AFEA6C028BCE1783CFE19A88C64E4ED6BFD638802A78457A5C25ABEA98BE9C6EF18A95504C324315EABE7C1EA50E754591E3EFD3D33D4AE47F82F8978ABC871C135133767ACC60683F065430C749C43893D73596B12D5835A78778D0140B2F63B32A5658308DD5BA6BBC49CF6692929FA6A966419404F9A2C216860E3F339EDDB49AD32C294BDB4C9C6BB0D1CC7B691C65968C3A0A5106291CD3810147C8A16B4BFE22968AD9D3890733F4AA9ACD8687A5B981653A4B1824004639956E8C1EDAF31A8224191E8ABD645D2901F5B164B4B93F98039A6EAEC6088
        , DSA.params_q = 0xE1FDFADD32F46B5035EEB3DB81F9974FBCA69BE2223E62FCA8C77989B2AACDF7
        }

arbitraryNamedEC :: Gen (PubKeyEC, PrivKeyEC)
arbitraryNamedEC = do
    name <- arbitraryCurveName
    let curve = ECC.getCurveByName name
    pair <- ECC.generate curve
    let d = ECDSA.private_d (snd pair)
        priv = PrivKeyEC_Named { privkeyEC_name = name, privkeyEC_priv = d }
        q = ECDSA.public_q (fst pair)
        pt = getSerializedPoint curve q
        pub = PubKeyEC_Named { pubkeyEC_name = name, pubkeyEC_pub = pt }
    return (pub, priv)

arbitraryExplicitPrimeCurve :: Gen (PubKeyEC, PrivKeyEC)
arbitraryExplicitPrimeCurve = do
    curve <- arbitraryPrimeCurve
    pair <- ECC.generate curve
    let cc   = ECC.common_curve curve
        c    = fp curve
        gen  = getSerializedPoint curve (ECC.ecc_g cc)
        d    = ECDSA.private_d (snd pair)
        priv =
            PrivKeyEC_Prime
                { privkeyEC_priv      = d
                , privkeyEC_a         = ECC.ecc_a cc
                , privkeyEC_b         = ECC.ecc_b cc
                , privkeyEC_prime     = ECC.ecc_p c
                , privkeyEC_generator = gen
                , privkeyEC_order     = ECC.ecc_n cc
                , privkeyEC_cofactor  = ECC.ecc_h cc
                , privkeyEC_seed      = 0
                }
        q    = ECDSA.public_q (fst pair)
        pt   = getSerializedPoint curve q
        pub  =
            PubKeyEC_Prime
                { pubkeyEC_pub        = pt
                , pubkeyEC_a          = ECC.ecc_a cc
                , pubkeyEC_b          = ECC.ecc_b cc
                , pubkeyEC_prime      = ECC.ecc_p c
                , pubkeyEC_generator  = gen
                , pubkeyEC_order      = ECC.ecc_n cc
                , pubkeyEC_cofactor   = ECC.ecc_h cc
                , pubkeyEC_seed       = 0
                }
    return (pub, priv)
  where
    fp (ECC.CurveFP c) = c
    fp _               = error "arbitraryExplicitPrimeCurve: assumption failed"

arbitraryCurveName :: Gen ECC.CurveName
arbitraryCurveName = elements allCurveNames

allCurveNames :: [ECC.CurveName]
allCurveNames =
    [ ECC.SEC_p112r1
    , ECC.SEC_p112r2
    , ECC.SEC_p128r1
    , ECC.SEC_p128r2
    , ECC.SEC_p160k1
    , ECC.SEC_p160r1
    , ECC.SEC_p160r2
    , ECC.SEC_p192k1
    , ECC.SEC_p192r1
    , ECC.SEC_p224k1
    , ECC.SEC_p224r1
    , ECC.SEC_p256k1
    , ECC.SEC_p256r1
    , ECC.SEC_p384r1
    , ECC.SEC_p521r1
    , ECC.SEC_t113r1
    , ECC.SEC_t113r2
    , ECC.SEC_t131r1
    , ECC.SEC_t131r2
    , ECC.SEC_t163k1
    , ECC.SEC_t163r1
    , ECC.SEC_t163r2
    , ECC.SEC_t193r1
    , ECC.SEC_t193r2
    , ECC.SEC_t233k1
    , ECC.SEC_t233r1
    , ECC.SEC_t239k1
    , ECC.SEC_t283k1
    , ECC.SEC_t283r1
    , ECC.SEC_t409k1
    , ECC.SEC_t409r1
    , ECC.SEC_t571k1
    , ECC.SEC_t571r1
    ]

primeCurves :: [ECC.Curve]
primeCurves = filter isPrimeCurve $ map ECC.getCurveByName allCurveNames
  where isPrimeCurve (ECC.CurveFP _) = True
        isPrimeCurve _               = False

arbitraryPrimeCurve :: Gen ECC.Curve
arbitraryPrimeCurve = elements primeCurves

getSerializedPoint :: ECC.Curve -> ECC.Point -> SerializedPoint
getSerializedPoint curve pt = SerializedPoint (serializePoint pt)
  where
    bs = i2ospOf_ (curveSizeBytes curve)

    serializePoint ECC.PointO      = B.singleton 0
    serializePoint (ECC.Point x y) = B.cons 4 (B.append (bs x) (bs y))

curveSizeBytes :: ECC.Curve -> Int
curveSizeBytes curve = (ECC.curveSizeBits curve + 7) `div` 8

instance Arbitrary SignatureALG where
    arbitrary = elements
        [ SignatureALG HashSHA1   PubKeyALG_RSA
        , SignatureALG HashMD5    PubKeyALG_RSA
        , SignatureALG HashMD2    PubKeyALG_RSA
        , SignatureALG HashSHA256 PubKeyALG_RSA
        , SignatureALG HashSHA384 PubKeyALG_RSA
        , SignatureALG HashSHA512 PubKeyALG_RSA
        , SignatureALG HashSHA224 PubKeyALG_RSA

        , SignatureALG HashSHA1   PubKeyALG_DSA
        , SignatureALG HashSHA224 PubKeyALG_DSA
        , SignatureALG HashSHA256 PubKeyALG_DSA

        , SignatureALG HashSHA224 PubKeyALG_EC
        , SignatureALG HashSHA256 PubKeyALG_EC
        , SignatureALG HashSHA384 PubKeyALG_EC
        , SignatureALG HashSHA512 PubKeyALG_EC
        ]

instance Arbitrary DateTime where
    arbitrary =
        let arbitraryElapsed = Elapsed . Seconds <$> choose (1, 100000000)
         in timeConvert <$> arbitraryElapsed

arbitraryCertificate :: PubKey -> Gen Certificate
arbitraryCertificate pubKey =
    Certificate <$> pure 2
                <*> arbitrary
                <*> arbitrary
                <*> arbitraryDN
                <*> arbitrary
                <*> arbitraryDN
                <*> pure pubKey
                <*> pure (Extensions Nothing)

instance Arbitrary Certificate where
    arbitrary = arbitrary >>= arbitraryCertificate

instance Arbitrary RevokedCertificate where
    arbitrary = RevokedCertificate <$> arbitrary
                                   <*> arbitrary
                                   <*> pure (Extensions Nothing)

instance Arbitrary CRL where
    arbitrary = CRL <$> pure 1
                    <*> arbitrary
                    <*> arbitraryDN
                    <*> arbitrary
                    <*> arbitrary
                    <*> arbitrary
                    <*> pure (Extensions Nothing)

arbitrarySignedExact :: (Show a, Eq a, ASN1Object a)
                     => a -> Gen (SignedExact a)
arbitrarySignedExact = objectToSignedExactF doSign
  where
    doSign _ = (,) <$> arbitrarySig <*> arbitrary
    arbitrarySig = B.pack <$> vector 16

arbitrarySignedCertificate :: PubKey -> Gen SignedCertificate
arbitrarySignedCertificate pubKey =
    arbitraryCertificate pubKey >>= arbitrarySignedExact

instance (Show a, Eq a, ASN1Object a, Arbitrary a) => Arbitrary (SignedExact a) where
    arbitrary = arbitrary >>= arbitrarySignedExact

arbitraryCertificateChain :: PubKey -> Gen CertificateChain
arbitraryCertificateChain pubKey = do
    leaf <- arbitrarySignedCertificate pubKey
    others <- resize 3 $ listOf (arbitrary >>= arbitrarySignedCertificate)
    return $ CertificateChain (leaf:others)
