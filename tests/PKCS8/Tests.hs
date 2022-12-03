-- | PKCS #8 tests.
module PKCS8.Tests (pkcs8Tests) where

import qualified Data.ByteString as B
import           Data.String (fromString)

import Crypto.Store.PKCS8

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import Util
import PKCS8.Instances ()

keyTests :: String -> TestTree
keyTests prefix =
    testGroup "PrivateKey"
        [ testCase "read outer" $ do
              kOuter <- readKeyFile fOuter
              length kOuter @?= 1
        , testCase "read inner" $ do
              kInner <- readKeyFile fInner
              length kInner @?= 1
        , testCase "same key"   $ do
              kInner <- readKeyFile fInner
              kOuter <- readKeyFile fOuter
              assertBool "keys differ" $
                  let [Unprotected kI] = kInner
                      [Unprotected kO] = kOuter
                   in kI == kO
        , testCase "write outer" $ do
              bs <- B.readFile fOuter
              let kOuter = readKeyFileFromMemory bs
                  [Unprotected kO] = kOuter
              writeKeyFileToMemory PKCS8Format [kO] @?= bs
        , testCase "write inner" $ do
              bs <- B.readFile fInner
              let kInner = readKeyFileFromMemory bs
                  [Unprotected kI] = kInner
              writeKeyFileToMemory TraditionalFormat [kI] @?= bs
        ]
  where
    fInner = testFile (prefix ++ "-unencrypted-trad.pem")
    fOuter = testFile (prefix ++ "-unencrypted-pkcs8.pem")

encryptedKeyTests :: String -> TestTree
encryptedKeyTests prefix =
    testGroup "EncryptedPrivateKey"
        [ keyTest "PBES1"  "pbes1"  8
        , keyTest "PBKDF2" "pbkdf2" 7
        , keyTest "Scrypt" "scrypt" 3
        ]
  where
    pwd = fromString "dontchangeme"

    keyTest name suffix count =
        let fE = testFile (prefix ++ "-encrypted-" ++ suffix ++ ".pem")
            fU = testFile (prefix ++ "-unencrypted-pkcs8.pem")
         in testGroup name
                [ testCase "read unencrypted" $ do
                      kU <- readKeyFile fU
                      length kU @?= 1
                , testCase "read encrypted"   $ do
                      kE <- readKeyFile fE
                      length kE @?= count
                , testCase "same keys"        $ do
                      kE <- readKeyFile fE
                      kU <- readKeyFile fU
                      assertBool "some keys differ" $
                          let [Unprotected key] = kU
                           in all (\(Protected getKey) -> getKey pwd == Right key) kE
                ]

testType :: TestName -> String -> TestTree
testType name prefix =
    testGroup name
        [ keyTests prefix
        , encryptedKeyTests prefix
        ]

propertyTests :: TestTree
propertyTests = localOption (QuickCheckMaxSize 5) $ testGroup "properties"
    [ testProperty "marshalling" $ \fmt l ->
        let r = readKeyFileFromMemory $ writeKeyFileToMemory fmt l
        in map Right l === map (recover $ fromString "not-used") r
    , testProperty "marshalling with encryption" $ \es k -> do
        p <- arbitrary
        let r = readKeyFileFromMemory <$> writeEncryptedKeyFileToMemory es p k
        return $ Right [Right k] === (map (recover p) <$> r)
    ]

pkcs8Tests :: TestTree
pkcs8Tests =
    testGroup "PKCS8"
        [ testType "RSA"                        "rsa"
        , testType "DSA"                        "dsa"
        , testType "EC (named curve)"           "ecdsa-p256"
        , testType "EC (explicit prime curve)"  "ecdsa-epc"
        , testType "X25519"                     "x25519"
        , testType "X448"                       "x448"
        , testType "Ed25519"                    "ed25519"
        , testType "Ed448"                      "ed448"
        , propertyTests
        ]
