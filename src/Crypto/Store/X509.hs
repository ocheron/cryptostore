-- |
-- Module      : Crypto.Store.X509
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Public keys, certificates and CRLs.
--
-- Presents an API similar to "Data.X509.Memory" and "Data.X509.File" but
-- provides support for public-key files and allows to write objects.
--
-- Functions related to private keys are available from "Crypto.Store.PKCS8".
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.Store.X509
    ( SignedObject()
    -- * Public keys
    , readPubKeyFile
    , readPubKeyFileFromMemory
    , pemToPubKey
    , writePubKeyFile
    , writePubKeyFileToMemory
    , pubKeyToPEM
    -- * Signed objects
    , readSignedObject
    , readSignedObjectFromMemory
    , writeSignedObject
    , writeSignedObjectToMemory
    -- * Reading and writing PEM files
    , readPEMs
    , writePEMs
    ) where

import Data.ASN1.Types
import Data.ASN1.BinaryEncoding
import Data.ASN1.Encoding
import Data.Maybe
import Data.Proxy
import qualified Data.X509 as X509
import qualified Data.ByteString as B
import           Crypto.Number.Basic (numBytes)
import qualified Crypto.PubKey.RSA as RSA

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Util
import Crypto.Store.PEM


-- | Class of signed objects convertible to PEM.
class (ASN1Object a, Eq a, Show a) => SignedObject a where
    signedObjectName :: proxy a -> String
    otherObjectNames :: proxy a -> [String]

instance SignedObject X509.Certificate where
    signedObjectName _ = "CERTIFICATE"
    otherObjectNames _ = ["X509 CERTIFICATE"]

instance SignedObject X509.CRL where
    signedObjectName _ = "X509 CRL"
    otherObjectNames _ = []

validObjectName :: SignedObject a => proxy a -> String -> Bool
validObjectName prx name =
    name == signedObjectName prx || name `elem` otherObjectNames prx


-- Reading from PEM format

-- | Read public keys from a PEM file.
readPubKeyFile :: FilePath -> IO [X509.PubKey]
readPubKeyFile path = accumulate <$> readPEMs path

-- | Read public keys from a bytearray in PEM format.
readPubKeyFileFromMemory :: B.ByteString -> [X509.PubKey]
readPubKeyFileFromMemory = either (const []) accumulate . pemParseBS

accumulate :: [PEM] -> [X509.PubKey]
accumulate = catMaybes . foldr (flip pemToPubKey) []

-- | Read a public key from a 'PEM' element and add it to the accumulator list.
pemToPubKey :: [Maybe X509.PubKey] -> PEM -> [Maybe X509.PubKey]
pemToPubKey acc pem =
    case decodeASN1' BER (pemContent pem) of
        Left _     -> acc
        Right asn1 -> run (getParser $ pemName pem) asn1 : acc

  where
    run p asn1 =
        case p asn1 of
            Right (pubKey, []) -> Just pubKey
            _                  -> Nothing

    getParser "PUBLIC KEY"           = fromASN1
    getParser "RSA PUBLIC KEY"       = runParseASN1State rsapkParser
    getParser _                      = const (Left undefined)

    rsapkParser = (\(RSAPublicKey pub) -> X509.PubKeyRSA pub) <$> parse

-- | Read signed objects from a PEM file (only one type at a time).
readSignedObject :: SignedObject a => FilePath -> IO [X509.SignedExact a]
readSignedObject path = accumulate' <$> readPEMs path

-- | Read signed objects from a bytearray in PEM format (only one type at a
-- time).
readSignedObjectFromMemory :: SignedObject a
                           => B.ByteString
                           -> [X509.SignedExact a]
readSignedObjectFromMemory = either (const []) accumulate' . pemParseBS

accumulate' :: forall a. SignedObject a => [PEM] -> [X509.SignedExact a]
accumulate' = foldr pemToSigned []
  where
    prx = Proxy :: Proxy a

    pemToSigned pem acc
        | validObjectName prx (pemName pem) =
            case X509.decodeSignedObject $ pemContent pem of
                Left _    -> acc
                Right obj -> obj : acc
        | otherwise = acc


-- Writing to PEM format

-- | Write public keys to a PEM file.
writePubKeyFile :: FilePath -> [X509.PubKey] -> IO ()
writePubKeyFile path = writePEMs path . map pubKeyToPEM

-- | Write public keys to a bytearray in PEM format.
writePubKeyFileToMemory :: [X509.PubKey] -> B.ByteString
writePubKeyFileToMemory = pemsWriteBS . map pubKeyToPEM

-- | Generate a PEM for a public key.
pubKeyToPEM :: X509.PubKey -> PEM
pubKeyToPEM pubKey = mkPEM "PUBLIC KEY" (encodeASN1S $ gMany asn1)
  where asn1 = toASN1 pubKey []

-- | Write signed objects to a PEM file.
writeSignedObject :: SignedObject a => FilePath -> [X509.SignedExact a] -> IO ()
writeSignedObject path = writePEMs path . map signedToPEM

-- | Write signed objects to a bytearray in PEM format.
writeSignedObjectToMemory :: SignedObject a => [X509.SignedExact a] -> B.ByteString
writeSignedObjectToMemory = pemsWriteBS . map signedToPEM

signedToPEM :: forall a. SignedObject a => X509.SignedExact a -> PEM
signedToPEM obj = mkPEM (signedObjectName prx) (X509.encodeSignedObject obj)
  where prx = Proxy :: Proxy a


-- RSA public keys

newtype RSAPublicKey = RSAPublicKey RSA.PublicKey

instance ASN1Elem e => ProduceASN1Object e RSAPublicKey where
    asn1s (RSAPublicKey pub) = asn1Container Sequence (n . e)
      where
        n = gIntVal (RSA.public_n pub)
        e = gIntVal (RSA.public_e pub)

instance Monoid e => ParseASN1Object e RSAPublicKey where
    parse = onNextContainer Sequence $ do
        IntVal modulus <- getNext
        IntVal pubexp <- getNext
        let pub = RSA.PublicKey { RSA.public_size = numBytes modulus
                                , RSA.public_n    = modulus
                                , RSA.public_e    = pubexp
                                }
        return (RSAPublicKey pub)
