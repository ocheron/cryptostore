-- | CMS tests.
module CMS.Tests (cmsTests) where

import Control.Monad

import qualified Data.ByteString as B
import           Data.String (fromString)
import           Data.Maybe (isNothing)

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import Crypto.Store.CMS
import Crypto.Store.PKCS8
import Crypto.Store.X509 (readSignedObject)

import CMS.Instances
import Util

message :: B.ByteString
message = fromString "hello, world\r\n"

testKey :: Int -> B.ByteString
testKey len = B.pack [0 .. toEnum (len - 1)]

hasType :: ContentType -> ContentInfo -> Bool
hasType t ci = t == getContentType ci

verifyInnerMessage :: B.ByteString -> ContentInfo -> IO ()
verifyInnerMessage msg ci = do
    assertBool "unexpected inner type" (hasType DataType ci)
    let DataCI bs = ci
    assertEqual "inner message differs" msg bs

dataTests :: TestTree
dataTests =
    testGroup "Data"
        [ testCase "read" $ do
              cms <- readCMSFile path
              length cms @?= count
              forM_ cms (verifyInnerMessage message)
        , testCase "write" $ do
              bs <- B.readFile path
              let ciList = [DataCI message]
              writeCMSFileToMemory ciList @?= bs
        ]
  where path  = testFile "cms-data.pem"
        count = 1

signedDataTests :: TestTree
signedDataTests =
    testCaseSteps "SignedData" $ \step -> do
        cms <- readCMSFile path
        assertEqual "unexpected parse count" (length names) (length cms)

        forM_ (zip [0..] cms) $ \(index, ci) -> do
            let name = names !! index

            step ("verifying " ++ name)
            assertBool "unexpected type" (hasType SignedDataType ci)
            let SignedDataCI sd = ci
            result <- verifySignedData withSignerKey sd
            assertJust result (verifyInnerMessage message)
  where path  = testFile "cms-signed-data.pem"
        names = [ "RSA"
                , "DSA"
                , "EC (named curve)"
                , "EC (explicit prime curve)"
                , "RSA-PSS"
                ]

envelopedDataTests :: TestTree
envelopedDataTests =
    testGroup "EnvelopedData"
        [ testKT "KTRI" path3 keys1
        , testKA "KARI" path4 keys1
        , test "KEKRI" path1 keys1 withRecipientKey
        , test "PWRI" path2 keys2 (\_ -> withRecipientPassword pwd)
        ]
  where test caseName path keys f = testCaseSteps caseName $ \step -> do
            cms <- readCMSFile path
            assertEqual "unexpected parse count" (length keys) (length cms)

            forM_ (zip [0..] cms) $ \(index, ci) -> do
                let (name, key) = keys !! index

                step ("testing " ++ name)
                assertBool "unexpected type" (hasType EnvelopedDataType ci)
                let EnvelopedDataCI ev = ci
                result <- openEnvelopedData (f key) ev
                assertRight result (verifyInnerMessage message)
        testKT caseName path keys = testCaseSteps caseName $ \step -> do
            let rsaPath = testFile "rsa-unencrypted-pkcs8.pem"
            [Unprotected priv] <- readKeyFile rsaPath

            cms <- readCMSFile path
            assertEqual "unexpected parse count" (length modes * length keys) (length cms)

            let pairs = [ (c, m) | c <- map fst keys1, m <- modes ]
            forM_ (zip pairs cms) $ \((c, m), ci) -> do
                step ("testing " ++ c ++ " with " ++ m)
                assertBool "unexpected type" (hasType EnvelopedDataType ci)
                let EnvelopedDataCI ev = ci
                result <- openEnvelopedData (withRecipientKeyTrans priv) ev
                assertRight result (verifyInnerMessage message)
        testKA caseName path keys = testCaseSteps caseName $ \step -> do
            let ecdsaKeyPath  = testFile "ecdsa-p256-unencrypted-pkcs8.pem"
                ecdsaCertPath = testFile "ecdsa-p256-self-signed-cert.pem"
            [Unprotected priv] <- readKeyFile ecdsaKeyPath
            [cert] <- readSignedObject ecdsaCertPath

            cms <- readCMSFile path
            assertEqual "unexpected parse count" (length mds * length keys) (length cms)

            let pairs = [ (c, h) | c <- map fst keys, h <- mds ]
            forM_ (zip pairs cms) $ \((c, h), ci) -> do
                step ("testing " ++ c ++ " with " ++ h)
                assertBool "unexpected type" (hasType EnvelopedDataType ci)
                let EnvelopedDataCI ev = ci
                result <- openEnvelopedData (withRecipientKeyAgree priv cert) ev
                assertRight result (verifyInnerMessage message)
        path1 = testFile "cms-enveloped-kekri-data.pem"
        path2 = testFile "cms-enveloped-pwri-data.pem"
        path3 = testFile "cms-enveloped-ktri-data.pem"
        path4 = testFile "cms-enveloped-kari-data.pem"
        pwd   = fromString "dontchangeme"
        keys2 = [ ("3DES_CBC",             testKey 24)
                , ("AES128_CBC",           testKey 16)
                , ("AES192_CBC",           testKey 24)
                , ("AES256_CBC",           testKey 32)
                , ("CAST5_CBC (128 bits)", testKey 16)
                , ("Camellia128_CBC",      testKey 16)
                , ("RC2 (128 bits)",       testKey 16)
                ]
        keys1 = keys2 ++
                [ ("AES128_ECB",           testKey 16)
                , ("AES192_ECB",           testKey 24)
                , ("AES256_ECB",           testKey 32)
                , ("Camellia128_ECB",      testKey 16)
                ]
        modes = [ "RSAES-PKCS1"
                , "RSAES-OAEP"
                ]
        mds   = [ "SHA1"
                , "SHA224"
                , "SHA256"
                , "SHA384"
                , "SHA512"
                ]

digestedDataTests :: TestTree
digestedDataTests =
    testCaseSteps "DigestedData" $ \step -> do
        cms <- readCMSFile path
        assertEqual "unexpected parse count" (length algs) (length cms)

        forM_ (zip [0..] cms) $ \(index, ci) -> do
            let (name, alg) = algs !! index

            step ("verifying " ++ name)
            assertBool "unexpected type" (hasType DigestedDataType ci)
            let DigestedDataCI dd = ci
                result = digestVerify dd
            assertJust result (verifyInnerMessage message)

            step ("digesting " ++ name)
            let ci' = digestData alg (DataCI message)
            ci @?= ci'
  where path  = testFile "cms-digested-data.pem"
        algs  = [ ("MD5",    DigestAlgorithm MD5)
                , ("SHA1",   DigestAlgorithm SHA1)
                , ("SHA224", DigestAlgorithm SHA224)
                , ("SHA256", DigestAlgorithm SHA256)
                , ("SHA384", DigestAlgorithm SHA384)
                , ("SHA512", DigestAlgorithm SHA512)
                ]

encryptedDataTests :: TestTree
encryptedDataTests =
    testCaseSteps "EncryptedData" $ \step -> do
        cms <- readCMSFile path
        assertEqual "unexpected parse count" (length keys) (length cms)

        forM_ (zip [0..] cms) $ \(index, ci) -> do
            let (name, key) = keys !! index

            step ("decrypting " ++ name)
            assertBool "unexpected type" (hasType EncryptedDataType ci)
            let EncryptedDataCI ed = ci
                result = decryptData key ed
            assertRight result (verifyInnerMessage message)

            step ("encrypting " ++ name)
            let params = edContentEncryptionParams ed
                ci'    = encryptData key params [] (DataCI message)
            Right ci @?= ci'
  where path  = testFile "cms-encrypted-data.pem"
        keys  = [ ("DES_CBC",              testKey  8)
                , ("3DES_CBC",             testKey 24)
                , ("AES128_CBC",           testKey 16)
                , ("AES192_CBC",           testKey 24)
                , ("AES256_CBC",           testKey 32)
                , ("CAST5_CBC (40 bits)",  testKey  5)
                , ("CAST5_CBC (128 bits)", testKey 16)
                , ("Camellia128_CBC",      testKey 16)
                , ("RC2 (40 bits)",        testKey  5)
                , ("RC2 (64 bits)",        testKey  8)
                , ("RC2 (128 bits)",       testKey 16)
                , ("DES_ECB",              testKey  8)
                , ("AES128_ECB",           testKey 16)
                , ("AES192_ECB",           testKey 24)
                , ("AES256_ECB",           testKey 32)
                , ("Camellia128_ECB",      testKey 16)
                ]

authEnvelopedDataTests :: TestTree
authEnvelopedDataTests =
    testCaseSteps "AuthEnvelopedData" $ \step -> do
        cms <- readCMSFile path
        assertEqual "unexpected parse count" count (length cms)

        forM_ (zip [0..] cms) $ \(index, ci) -> do
            step ("testing vector " ++ show (index :: Int))
            assertBool "unexpected type" (hasType AuthEnvelopedDataType ci)
            let AuthEnvelopedDataCI ae = ci
            result <- openAuthEnvelopedData (withRecipientPassword pwd) ae
            assertRight result (verifyInnerMessage msg)

            step ("testing encoded vector " ++ show index)
            let [Just ci'] = pemToContentInfo [] (contentInfoToPEM ci)
                AuthEnvelopedDataCI ae' = ci'
            result' <- openAuthEnvelopedData (withRecipientPassword pwd) ae'
            assertRight result' (verifyInnerMessage msg)
  where path  = testFile "cms-auth-enveloped-data-rfc6476.pem"
        pwd   = fromString "password"
        msg   = fromString "Some test data\NUL"
        count = 2

propertyTests :: TestTree
propertyTests = localOption (QuickCheckMaxSize 5) $ testGroup "properties"
    [ testProperty "marshalling" $ \l ->
        let bs = writeCMSFileToMemory l
        in label (sizeRange bs) $ l === readCMSFileFromMemory bs
    , testProperty "signing" $ \alg ci ->
        collect alg $ do
            (sigFns, verFn) <- scale succ (arbitrarySigVer alg)
            r <- signData sigFns ci
            let Right (SignedDataCI sd) = r
            r' <- verifySignedData verFn sd
            return (Just ci === r')
    , testProperty "enveloping" $ \alg ci ->
        collect alg $ do
            (oinfo, key, envFns, devFn, attrs) <- getCommon alg
            r <- envelopData oinfo key alg envFns attrs ci
            let Right (EnvelopedDataCI ev) = r
            r' <- openEnvelopedData devFn ev
            return (Right ci === r')
    , testProperty "digesting" $ \alg ci ->
        collect alg $
            let DigestedDataCI dd = digestData alg ci
             in Just ci === digestVerify dd
    , testProperty "encrypting" $ \alg ci ->
        collect alg $ do
            key <- generateKey alg
            attrs <- arbitraryAttributes
            let Right (EncryptedDataCI ed) = encryptData key alg attrs ci
            return (Right ci === decryptData key ed)
    , testProperty "authenticating" $ \alg dig ci ->
        collect alg $ do
            (oinfo, key, envFns, devFn, uAttrs) <- getCommon alg
            aAttrs <- if isNothing dig then pure [] else arbitraryAttributes
            r <- generateAuthenticatedData oinfo key alg dig envFns aAttrs uAttrs ci
            let Right (AuthenticatedDataCI ad) = r
            r' <- verifyAuthenticatedData devFn ad
            return (Right ci === r')
    , testProperty "enveloping with authentication" $ \alg ci ->
        collect alg $ do
            (oinfo, key, envFns, devFn, uAttrs) <- getCommon alg
            aAttrs <- arbitraryAttributes
            r <- authEnvelopData oinfo key alg envFns aAttrs uAttrs ci
            let Right (AuthEnvelopedDataCI ae) = r
            r' <- openAuthEnvelopedData devFn ae
            return (Right ci === r')
    ]
  where
    sizeRange bs =
        let n = B.length bs `div` 1024
         in show n ++ " .. " ++ show (n + 1) ++ " KB"

getCommon :: HasKeySize params
          => params
          -> Gen (OriginatorInfo, B.ByteString, [ProducerOfRI Gen], ConsumerOfRI Gen, [Attribute])
getCommon alg = do
    oinfo <- arbitrary
    key <- generateKey alg
    (envFns, devFn) <- scale succ (arbitraryEnvDev key)
    attrs <- arbitraryAttributes
    return (oinfo, key, envFns, devFn, attrs)

cmsTests :: TestTree
cmsTests =
    testGroup "CMS"
        [ dataTests
        , signedDataTests
        , envelopedDataTests
        , digestedDataTests
        , encryptedDataTests
        , authEnvelopedDataTests
        , propertyTests
        ]
