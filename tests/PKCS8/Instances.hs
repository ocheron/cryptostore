{-# OPTIONS_GHC -fno-warn-orphans #-}
-- | Orphan instances.
module PKCS8.Instances
    ( arbitraryPassword
    ) where

import Test.Tasty.QuickCheck

import Crypto.Store.CMS
import Crypto.Store.PKCS5
import Crypto.Store.PKCS8

import CMS.Instances

instance Arbitrary PBEParameter where
    arbitrary = do
        salt <- generateSalt 8
        PBEParameter salt <$> choose (1,512)

instance Arbitrary PBES2Parameter where
    arbitrary = PBES2Parameter <$> arbitrary <*> arbitrary

instance Arbitrary EncryptionScheme where
    arbitrary = oneof [ PBES2 <$> arbitrary
                      , PBE_MD5_DES_CBC <$> arbitrary
                      , PBE_SHA1_DES_CBC <$> arbitrary
                      , PBE_SHA1_RC4_128 <$> arbitrary
                      , PBE_SHA1_RC4_40 <$> arbitrary
                      , PBE_SHA1_DES_EDE3_CBC <$> arbitrary
                      , PBE_SHA1_DES_EDE2_CBC <$> arbitrary
                      , PBE_SHA1_RC2_128 <$> arbitrary
                      , PBE_SHA1_RC2_40 <$> arbitrary
                      ]

instance Arbitrary PrivateKeyFormat where
    arbitrary = elements [ TraditionalFormat, PKCS8Format ]

instance Arbitrary a => Arbitrary (FormattedKey a) where
    arbitrary = FormattedKey <$> arbitrary <*> arbitrary
