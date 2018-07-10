-- | CMS tests.
module CMS.Tests (cmsTests) where

import Control.Monad

import qualified Data.ByteString as B
import           Data.String (fromString)

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck

import Crypto.Store.CMS

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

envelopedDataTests :: TestTree
envelopedDataTests =
    testGroup "EnvelopedData"
        [ test "KEKRI" path1 withRecipientKey
        , test "PWRI" path2 (\_ -> withRecipientPassword pwd)
        ]
  where test caseName path f = testCaseSteps caseName $ \step -> do
            cms <- readCMSFile path
            assertEqual "unexpected parse count" (length keys) (length cms)

            forM_ (zip [0..] cms) $ \(index, ci) -> do
                let (name, key) = keys !! index

                step ("testing " ++ name)
                assertBool "unexpected type" (hasType EnvelopedDataType ci)
                let EnvelopedDataCI ev = ci
                    result = openEnvelopedData (f key) ev
                assertRight result (verifyInnerMessage message)
        path1 = testFile "cms-enveloped-kekri-data.pem"
        path2 = testFile "cms-enveloped-pwri-data.pem"
        pwd   = fromString "dontchangeme"
        keys  = [ ("3DES_CBC",             testKey 24)
                , ("AES128_CBC",           testKey 16)
                , ("AES192_CBC",           testKey 24)
                , ("AES256_CBC",           testKey 32)
                , ("CAST5_CBC (128 bits)", testKey 16)
                , ("Camellia128_CBC",      testKey 16)
                , ("AES128_ECB",           testKey 16)
                , ("AES192_ECB",           testKey 24)
                , ("AES256_ECB",           testKey 32)
                , ("Camellia128_ECB",      testKey 16)
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
        algs  = [ ("MD5",    DigestType MD5)
                , ("SHA1",   DigestType SHA1)
                , ("SHA224", DigestType SHA224)
                , ("SHA256", DigestType SHA256)
                , ("SHA384", DigestType SHA384)
                , ("SHA512", DigestType SHA512)
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
                , ("DES_ECB",              testKey  8)
                , ("AES128_ECB",           testKey 16)
                , ("AES192_ECB",           testKey 24)
                , ("AES256_ECB",           testKey 32)
                , ("Camellia128_ECB",      testKey 16)
                ]

propertyTests :: TestTree
propertyTests = localOption (QuickCheckMaxSize 5) $ testGroup "properties"
    [ testProperty "marshalling" $ \l ->
        let bs = writeCMSFileToMemory l
        in label (sizeRange bs) $ l === readCMSFileFromMemory bs
    , testProperty "enveloping" $ \alg ci ->
        collect alg $ do
            key <- generateKey alg
            (envFns, devFn) <- scale succ (arbitraryEnvDev key)
            attrs <- arbitraryAttributes
            Right (EnvelopedDataCI ev) <- envelopData key alg envFns attrs ci
            return (Right ci === openEnvelopedData devFn ev)
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
    ]
  where
    sizeRange bs =
        let n = B.length bs `div` 1024
         in show n ++ " .. " ++ show (n + 1) ++ " KB"

cmsTests :: TestTree
cmsTests =
    testGroup "CMS"
        [ dataTests
        , envelopedDataTests
        , digestedDataTests
        , encryptedDataTests
        , propertyTests
        ]
