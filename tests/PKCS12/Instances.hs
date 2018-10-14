{-# OPTIONS_GHC -fno-warn-orphans #-}
-- | Orphan instances.
module PKCS12.Instances
    ( arbitraryPassword
    , arbitraryAlias
    , arbitraryIntegrityParams
    , arbitraryPKCS12
    ) where

import qualified Data.ByteArray as B
import           Data.ByteString (ByteString)
import           Data.Semigroup

import Test.Tasty.QuickCheck

import Crypto.Store.PKCS12
import Crypto.Store.PKCS5

import CMS.Instances
import PKCS8.Instances ()

arbitrarySmall :: Gen ByteString
arbitrarySmall = resize 10 (B.pack <$> arbitrary)

arbitraryAlias :: Gen String
arbitraryAlias = resize 16 asciiChar
  where asciiChar = listOf $ choose ('\x20','\x7f')

arbitraryIntegrityParams :: Gen IntegrityParams
arbitraryIntegrityParams = (,) <$> arbitraryIntegrityDigest <*> arbitrary

arbitraryPKCS12 :: Password -> Gen PKCS12
arbitraryPKCS12 pwd = do
    p <- one
    ps <- listOf one
    return (foldr (<>) p ps)
  where
    one = oneof [ unencrypted <$> arbitrary
                , arbitrary >>= arbitraryEncrypted
                ]

    arbitraryEncrypted sc = do
        alg <- arbitrary
        case encrypted alg pwd sc of
            Left e -> fail (show e)
            Right aSafe -> return aSafe

instance Arbitrary SafeContents where
    arbitrary = SafeContents <$> arbitrary

instance Arbitrary info => Arbitrary (Bag info) where
    arbitrary = do
        info <- arbitrary
        attrs <- arbitraryAttributes
        return Bag { bagInfo = info, bagAttributes = attrs }

instance Arbitrary CertInfo where
    arbitrary = CertX509 <$> arbitrary

instance Arbitrary CRLInfo where
    arbitrary = CRLX509 <$> arbitrary

instance Arbitrary SafeInfo where
    arbitrary = oneof [ KeyBag <$> arbitrary
                      , PKCS8ShroudedKeyBag <$> arbitraryShrouded
                      , CertBag <$> arbitrary
                      , CRLBag <$> arbitrary
                      --, SecretBag <$> arbitrary
                      , SafeContentsBag <$> arbitrary
                      ]

arbitraryShrouded :: Gen PKCS5
arbitraryShrouded = do
    alg <- arbitrary
    bs <- arbitrarySmall -- fake content, tested with PKCS8
    return PKCS5 { encryptionAlgorithm = alg, encryptedData = bs }
