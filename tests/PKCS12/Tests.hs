-- | PKCS #12 tests.
module PKCS12.Tests (pkcs12Tests) where

import Control.Monad (forM_)

import Data.PEM (pemContent)
import Data.String (fromString)

import Crypto.Store.PKCS12
import Crypto.Store.PKCS8
import Crypto.Store.X509 (readSignedObject)

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import Util
import PKCS12.Instances
import X509.Instances

testType :: TestName -> String -> TestTree
testType caseName prefix = testCaseSteps caseName $ \step -> do
    let fKey  = testFile (prefix ++ "-unencrypted-pkcs8.pem")
        fCert = testFile (prefix ++ "-self-signed-cert.pem")
        p12   = testFile (prefix ++ "-pkcs12.pem")

    step "Reading PKCS #12 files"
    pems <- readPEMs p12
    length pems @?= length names

    step "Reading private key"
    [Unprotected key] <- readKeyFile fKey

    step "Reading certificate"
    certs <- readSignedObject fCert

    forM_ (zip names pems) $ \(name, pem) -> do
        let r = readP12FileFromMemory (pemContent pem)

        assertRight r $ \integrity ->
            assertRight (recover pwd integrity) $ \privacy ->
                assertRight (recover pwd $ unPKCS12 privacy) $ \scs -> do
                    step ("Testing " ++ name)
                    recover pwd (getAllSafeKeys scs) @?= Right [key]
                    getAllSafeX509Certs scs @?= certs
  where
    pwd :: Password
    pwd = fromString "dontchangeme"

    nameIntegrity n = "integrity with " ++ n
    namePrivacy t n = t ++ " privacy with " ++ n

    integrityNames = map nameIntegrity integrityModes
    privacyNames t = ("without " ++ t ++ " privacy") :
                     map (namePrivacy t) privacyModes

    names = [ "without integrity" ] ++ integrityNames ++
            privacyNames "certificate" ++ privacyNames "private-key"

    integrityModes = [ "SHA-1"
                     , "SHA-256"
                     , "SHA-384"
                     ]

    privacyModes   = [ "aes-128-cbc"
                     , "PBE-SHA1-RC2-128"
                     , "PBE-SHA1-RC2-40"
                     ]

propertyTests :: TestTree
propertyTests = localOption (QuickCheckMaxSize 5) $ testGroup "properties"
    [ testProperty "marshalling" $ do
        pE <- arbitraryPassword
        c <- arbitraryPKCS12 pE
        let r = readP12FileFromMemory $ writeUnprotectedP12FileToMemory c
        return $ Right (Right c) === (recover (fromString "not-used") <$> r)
    , testProperty "marshalling with authentication" $ do
        params <- arbitraryIntegrityParams
        c <- arbitraryPassword >>= arbitraryPKCS12
        pI <- arbitraryPassword
        let r = readP12FileFromMemory <$> writeP12FileToMemory params pI c
        return $ Right (Right (Right c)) === (fmap (recover pI) <$> r)
    , localOption (QuickCheckTests 20) $ testProperty "converting credentials" $
        \pChain pKey privKey ->
            testCredConv privKey toCredential (fromCredential pChain pKey)
    , localOption (QuickCheckTests 20) $ testProperty "converting named credentials" $
        \pChain pKey privKey -> do
            name <- arbitraryAlias
            testCredConv privKey
                (toNamedCredential name)
                (fromNamedCredential name pChain pKey)
    ]
  where
    testCredConv privKey to from = do
        pwd <- arbitraryPassword
        chain <- arbitrary >>= arbitraryCertificateChain
        chain' <- shuffleCertificateChain chain
        let cred = (chain, privKey)
            r = from pwd (chain', privKey) >>= recover pwd . to
        return $ Right (Just cred) === r

pkcs12Tests :: TestTree
pkcs12Tests =
    testGroup "PKCS12"
        [ testType "RSA"                        "rsa"
        , testType "EC (named curve)"           "ecdsa-p256"
        , propertyTests
        ]
