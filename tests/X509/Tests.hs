-- | X.509 tests.
module X509.Tests (x509Tests) where

import qualified Data.ByteString as B
import           Data.X509

import Crypto.Store.X509

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import Util
import X509.Instances ()

keyTests :: TestName -> String -> Int -> TestTree
keyTests name prefix count =
    testGroup name
        [ testCase "read public key" $ do
              keys <- readPubKeyFile fKey
              length keys @?= count
        , testCase "read certificate" $ do
              cert <- readSignedObject fCert :: IO [SignedCertificate]
              length cert @?= 1
        , testCase "same key" $ do
              cert <- readSignedObject fCert :: IO [SignedCertificate]
              keys <- readPubKeyFile fKey
              assertBool "keys differ" $
                  let [c] = cert
                      key = certPubKey (signedObject (getSigned c))
                   in all (== key) keys
        , testCase "write certificate" $ do
              bs <- B.readFile fCert
              let objs = readSignedObjectFromMemory bs :: [SignedCertificate]
              writeSignedObjectToMemory objs @?= bs
        , testCase "write public key" $ do
              bs <- B.readFile fKey
              let (key : _) = readPubKeyFileFromMemory bs
              assertBool "first key differs" $
                  writePubKeyFileToMemory [key] `B.isPrefixOf` bs
        ]
  where
    fCert = testFile (prefix ++ "-self-signed-cert.pem")
    fKey  = testFile (prefix ++ "-public.pem")

propertyTests :: TestTree
propertyTests = localOption (QuickCheckMaxSize 5) $ testGroup "properties"
    [ testProperty "marshalling public keys" $ \keys ->
          keys === readPubKeyFileFromMemory (writePubKeyFileToMemory keys)
    , testProperty "marshalling certificates" $ \objs ->
          asCerts objs === writeReadObjs objs
    , testProperty "marshalling CRLs" $ \objs ->
          asCRLs objs === writeReadObjs objs
    ]
  where
    writeReadObjs :: SignedObject a => [SignedExact a] -> [SignedExact a]
    writeReadObjs = readSignedObjectFromMemory . writeSignedObjectToMemory

    asCerts = id :: [SignedCertificate] -> [SignedCertificate]
    asCRLs  = id :: [SignedCRL] -> [SignedCRL]

x509Tests :: TestTree
x509Tests =
    testGroup "X509"
        [ keyTests "RSA"                        "rsa"        2
        , keyTests "DSA"                        "dsa"        1
        , keyTests "EC (named curve)"           "ecdsa-p256" 1
--        , keyTests "EC (explicit prime curve)"  "ecdsa-epc"  1
        , keyTests "X25519"                     "x25519"     1
        , keyTests "X448"                       "x448"       1
        , keyTests "Ed25519"                    "ed25519"    1
        , keyTests "Ed448"                      "ed448"      1
        , propertyTests
        ]
