{-# OPTIONS_GHC -fno-warn-orphans #-}
-- | Orphan instances.
module CMS.Instances
    ( arbitraryPassword
    , arbitraryAttributes
    , arbitraryEnvDev
    ) where

import           Data.ASN1.Types
import qualified Data.ByteArray as B
import           Data.ByteString (ByteString)

import Test.Tasty.QuickCheck

import Crypto.Store.CMS

import X509.Instances

arbitrarySmall :: Gen ByteString
arbitrarySmall = resize 10 (B.pack <$> arbitrary)

arbitraryPassword :: Gen ByteString
arbitraryPassword = resize 16 (B.pack <$> asciiChar)
  where asciiChar = listOf $ choose (0x20,0x7f)

instance Arbitrary ContentInfo where
    arbitrary = sized $ \n ->
        if n == 0
            then DataCI <$> arbitraryMessage
            else oneof [ DataCI <$> arbitraryMessage
                       , arbitraryEnvelopedData
                       , arbitraryDigestedData
                       , arbitraryEncryptedData
                       ]
      where
        arbitraryMessage :: Gen ByteString
        arbitraryMessage = resize 2048 (B.pack <$> arbitrary)

        arbitraryEnvelopedData :: Gen ContentInfo
        arbitraryEnvelopedData = do
            (alg, key, attrs) <- getCommon
            (envFns, _) <- arbitraryEnvDev key
            inner <- scale (subtract $ length envFns) arbitrary
            envelopData key alg envFns attrs inner >>= either fail return

        arbitraryDigestedData :: Gen ContentInfo
        arbitraryDigestedData = do
            inner <- scale pred arbitrary
            dt <- arbitrary
            return $ digestData dt inner

        arbitraryEncryptedData :: Gen ContentInfo
        arbitraryEncryptedData = do
            (alg, key, attrs) <- getCommon
            inner <- scale pred arbitrary
            either fail return $ encryptData key alg attrs inner

        getCommon :: (HasKeySize params, Arbitrary params, B.ByteArray key)
                  => Gen (params, key, [Attribute])
        getCommon = do
            alg   <- arbitrary
            key   <- generateKey alg
            attrs <- arbitraryAttributes
            return (alg, key, attrs)

instance Arbitrary Attribute where
    arbitrary = do
        oid  <- arbitraryOID
        vals <- resize 3 $ listOf1 (OctetString <$> arbitrarySmall)
        return Attribute { attrType = oid, attrValues = vals }

arbitraryAttributes :: Gen [Attribute]
arbitraryAttributes = resize 3 $ listOf arbitrary

instance Arbitrary DigestType where
    arbitrary = elements
        [ DigestType MD5
        , DigestType SHA1
        , DigestType SHA224
        , DigestType SHA256
        , DigestType SHA384
        , DigestType SHA512
        ]

instance Arbitrary PBKDF2_PRF where
    arbitrary = elements
        [ PBKDF2_SHA1
        , PBKDF2_SHA256
        , PBKDF2_SHA512
        ]

instance Arbitrary ContentEncryptionAlg where
    arbitrary = elements
        [ CBC DES
        , CBC DES_EDE3
        , CBC AES128
        , CBC AES192
        , CBC AES256
        , CBC CAST5
        , CBC Camellia128

        , ECB DES
        , ECB AES128
        , ECB AES192
        , ECB AES256
        , ECB Camellia128

        , CFB DES
        , CFB AES128
        , CFB AES192
        , CFB AES256
        , CFB Camellia128

        , CTR Camellia128
        ]

instance Arbitrary ContentEncryptionParams where
    arbitrary = arbitrary >>= generateEncryptionParams

instance Arbitrary KeyDerivationFunc where
    arbitrary = do
        salt <- generateSalt 8
        oneof [ pbkdf2 salt , scrypt salt ]
      where
        pbkdf2 salt = do
            iters <- choose (1,512)
            pf <- arbitrary
            return PBKDF2 { pbkdf2Salt           = salt
                          , pbkdf2IterationCount = iters
                          , pbkdf2KeyLength      = Nothing
                          , pbkdf2Prf            = pf
                          }
        scrypt salt = do
            (n, r, p) <- elements [ (16, 1, 1) , (1024, 8, 16) ]
            return Scrypt { scryptSalt      = salt
                          , scryptN         = n
                          , scryptR         = r
                          , scryptP         = p
                          , scryptKeyLength = Nothing
                          }

instance Arbitrary KeyEncryptionParams where
    arbitrary = oneof
        [ PWRIKEK <$> arbitrary
        , return AES128_WRAP
        , return AES192_WRAP
        , return AES256_WRAP
        , return AES128_WRAP_PAD
        , return AES192_WRAP_PAD
        , return AES256_WRAP_PAD
        , return DES_EDE3_WRAP
        ]

instance Arbitrary OtherKeyAttribute where
    arbitrary = do
        oid <- arbitraryOID
        vals <- resize 3 $ listOf1 (OctetString <$> arbitrarySmall)
        return OtherKeyAttribute { keyAttrId = oid, keyAttr = vals }

instance Arbitrary KEKIdentifier where
    arbitrary = do
        kid <- arbitrarySmall
        KEKIdentifier kid Nothing <$> arbitrary

arbitraryEnvDev :: ContentEncryptionKey
                -> Gen ([ProducerOfRI Gen], ConsumerOfRI)
arbitraryEnvDev cek = sized $ \n -> do
    (envFn, devFn) <- onePair
    otherPairs <- resize (min (pred n) 3) $ listOf onePair
    envFns <- shuffle (envFn : map fst otherPairs)
    return (envFns, devFn)
  where
    len     = B.length cek
    onePair = oneof [ arbitraryKEK, arbitraryPW ]

    arbitraryKEK = do
        kid <- arbitrary
        es  <- arbitraryAlg
        key <- generateKey es
        return (forKeyRecipient key kid es, withRecipientKey key)

    arbitraryPW  = do
        pwd <- arbitraryPassword
        kdf <- arbitrary
        cea <- arbitrary `suchThat` notModeCTR
        let es = PWRIKEK cea
        return (forPasswordRecipient pwd kdf es, withRecipientPassword pwd)

    arbitraryAlg
        | len == 24      = oneof [ return AES128_WRAP
                                 , return AES192_WRAP
                                 , return AES256_WRAP
                                 , return AES128_WRAP_PAD
                                 , return AES192_WRAP_PAD
                                 , return AES256_WRAP_PAD
                                 , return DES_EDE3_WRAP
                                 ]
        | mod len 8 == 0 = oneof [ return AES128_WRAP
                                 , return AES192_WRAP
                                 , return AES256_WRAP
                                 , return AES128_WRAP_PAD
                                 , return AES192_WRAP_PAD
                                 , return AES256_WRAP_PAD
                                 ]
        | otherwise      = oneof [ return AES128_WRAP_PAD
                                 , return AES192_WRAP_PAD
                                 , return AES256_WRAP_PAD
                                 ]

    -- key wrapping in PWRIKEK is incompatible with CTR mode so we must never
    -- generate this combination
    notModeCTR params =
        case getContentEncryptionAlg params of
            CTR _ -> False
            _     -> True
