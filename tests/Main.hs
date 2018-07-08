-- | cryptostore test suite.
module Main (main) where

import Test.Tasty

import KeyWrap.AES
import KeyWrap.TripleDES
import CMS.Tests
import PKCS8.Tests

-- | Run the test suite.
main :: IO ()
main = defaultMain $ testGroup "cryptostore"
    [ aeskwTests
    , tripledeskwTests
    , cmsTests
    , pkcs8Tests
    ]
