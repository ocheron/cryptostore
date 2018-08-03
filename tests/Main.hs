-- | cryptostore test suite.
module Main (main) where

import Test.Tasty

import KeyWrap.AES
import KeyWrap.TripleDES
import KeyWrap.RC2
import Cipher.RC2
import CMS.Tests
import PKCS12.Tests
import PKCS8.Tests

-- | Run the test suite.
main :: IO ()
main = defaultMain $ testGroup "cryptostore"
    [ aeskwTests
    , tripledeskwTests
    , rc2kwTests
    , rc2Tests
    , cmsTests
    , pkcs8Tests
    , pkcs12Tests
    ]
