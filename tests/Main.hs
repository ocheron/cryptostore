-- | cryptostore test suite.
module Main (main) where

import Test.Tasty

import KeyWrap.AES
import KeyWrap.TripleDES
import Cipher.RC2
import CMS.Tests
import PKCS8.Tests

-- | Run the test suite.
main :: IO ()
main = defaultMain $ testGroup "cryptostore"
    [ aeskwTests
    , tripledeskwTests
    , rc2Tests
    , cmsTests
    , pkcs8Tests
    ]
