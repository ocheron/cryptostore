-- |
-- Module      : Crypto.Store.PKCS8
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Private-Key Information Syntax, aka PKCS #8.
--
-- Presents an API similar to "Data.X509.Memory" and "Data.X509.File" but
-- allows to write private keys and provides support for password-based
-- encryption.
--
-- Functions to read a private key return an object wrapped in the
-- 'OptProtected' data type.
--
-- Functions related to public keys, certificates and CRLs are available from
-- "Crypto.Store.X509".
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE UndecidableInstances #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Crypto.Store.PKCS8
    ( readKeyFile
    , readKeyFileFromMemory
    , pemToKey
    , writeKeyFile
    , writeKeyFileToMemory
    , keyToPEM
    , writeEncryptedKeyFile
    , writeEncryptedKeyFileToMemory
    , encryptKeyToPEM
    -- * Serialization formats
    , PrivateKeyFormat(..)
    , FormattedKey(..)
    -- * Password-based protection
    , ProtectionPassword
    , emptyNotTerminated
    , fromProtectionPassword
    , toProtectionPassword
    , OptProtected(..)
    , recover
    , recoverA
    -- * Reading and writing PEM files
    , readPEMs
    , writePEMs
    ) where

import Control.Applicative
import Control.Monad (void, when)

import Data.ASN1.Types
import Data.ASN1.BinaryEncoding
import Data.ASN1.BitArray
import Data.ASN1.Encoding
import Data.ByteArray (ByteArrayAccess, convert)
import Data.Maybe
import qualified Data.X509 as X509
import qualified Data.ByteString as B
import           Crypto.Error
import           Crypto.Number.Serialize (i2osp, i2ospOf_, os2ip)
import qualified Crypto.PubKey.Curve25519 as X25519
import qualified Crypto.PubKey.Curve448 as X448
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.Ed448 as Ed448
import qualified Crypto.PubKey.RSA as RSA

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Attribute
import Crypto.Store.CMS.Util
import Crypto.Store.Error
import Crypto.Store.PEM
import Crypto.Store.PKCS5
import Crypto.Store.PKCS8.EC
import Crypto.Store.Util

-- | Data type for objects that are possibly protected with a password.
data OptProtected a = Unprotected a
                      -- ^ Value is unprotected
                    | Protected (ProtectionPassword -> Either StoreError a)
                      -- ^ Value is protected with a password

instance Functor OptProtected where
    fmap f (Unprotected x) = Unprotected (f x)
    fmap f (Protected g)   = Protected (fmap f . g)

-- | Try to recover an 'OptProtected' content using the specified password.
recover :: ProtectionPassword -> OptProtected a -> Either StoreError a
recover _   (Unprotected x) = Right x
recover pwd (Protected f)   = f pwd

-- | Try to recover an 'OptProtected' content in an applicative context.  The
-- applicative password is used if necessary.
--
-- > import qualified Data.ByteString as B
-- > import           Crypto.Store.PKCS8
-- >
-- > [encryptedKey] <- readKeyFile "privkey.pem"
-- > let askForPassword = putStr "Please enter password: " >> B.getLine
-- > result <- recoverA (toProtectionPassword <$> askForPassword) encryptedKey
-- > case result of
-- >     Left err  -> putStrLn $ "Unable to recover key: " ++ show err
-- >     Right key -> print key
recoverA :: Applicative f
         => f ProtectionPassword
         -> OptProtected a
         -> f (Either StoreError a)
recoverA _   (Unprotected x) = pure (Right x)
recoverA get (Protected f)   = fmap f get


-- Reading from PEM format

-- | Read private keys from a PEM file.
readKeyFile :: FilePath -> IO [OptProtected X509.PrivKey]
readKeyFile path = accumulate <$> readPEMs path

-- | Read private keys from a bytearray in PEM format.
readKeyFileFromMemory :: B.ByteString -> [OptProtected X509.PrivKey]
readKeyFileFromMemory = either (const []) accumulate . pemParseBS

accumulate :: [PEM] -> [OptProtected X509.PrivKey]
accumulate = catMaybes . foldr (flip pemToKey) []

-- | Read a private key from a 'PEM' element and add it to the accumulator list.
pemToKey :: [Maybe (OptProtected X509.PrivKey)] -> PEM -> [Maybe (OptProtected X509.PrivKey)]
pemToKey acc pem =
    case decodeASN1' BER (pemContent pem) of
        Left _     -> acc
        Right asn1 -> run (getParser $ pemName pem) asn1 : acc

  where
    run p = either (const Nothing) Just . runParseASN1 p

    allTypes  = unFormat <$> parse
    rsa       = X509.PrivKeyRSA . unFormat <$> parse
    dsa       = X509.PrivKeyDSA . DSA.toPrivateKey . unFormat <$> parse
    ecdsa     = X509.PrivKeyEC . unFormat <$> parse
    x25519    = X509.PrivKeyX25519 <$> parseModern
    x448      = X509.PrivKeyX448 <$> parseModern
    ed25519   = X509.PrivKeyEd25519 <$> parseModern
    ed448     = X509.PrivKeyEd448 <$> parseModern
    encrypted = inner . decrypt <$> parse

    getParser "PRIVATE KEY"           = Unprotected <$> allTypes
    getParser "RSA PRIVATE KEY"       = Unprotected <$> rsa
    getParser "DSA PRIVATE KEY"       = Unprotected <$> dsa
    getParser "EC PRIVATE KEY"        = Unprotected <$> ecdsa
    getParser "X25519 PRIVATE KEY"    = Unprotected <$> x25519
    getParser "X448 PRIVATE KEY"      = Unprotected <$> x448
    getParser "ED25519 PRIVATE KEY"   = Unprotected <$> ed25519
    getParser "ED448 PRIVATE KEY"     = Unprotected <$> ed448
    getParser "ENCRYPTED PRIVATE KEY" = Protected   <$> encrypted
    getParser _                       = empty

    inner decfn pwd = do
        decrypted <- decfn pwd
        asn1 <- mapLeft DecodingError $ decodeASN1' BER decrypted
        case run allTypes asn1 of
            Nothing -> Left (ParseFailure "No key parsed after decryption")
            Just k  -> return k


-- Writing to PEM format

-- | Write unencrypted private keys to a PEM file.
writeKeyFile :: PrivateKeyFormat -> FilePath -> [X509.PrivKey] -> IO ()
writeKeyFile fmt path = writePEMs path . map (keyToPEM fmt)

-- | Write unencrypted private keys to a bytearray in PEM format.
writeKeyFileToMemory :: PrivateKeyFormat -> [X509.PrivKey] -> B.ByteString
writeKeyFileToMemory fmt = pemsWriteBS . map (keyToPEM fmt)

-- | Write a PKCS #8 encrypted private key to a PEM file.
--
-- If multiple keys need to be stored in the same file, use functions
-- 'encryptKeyToPEM' and 'writePEMs'.
--
-- Fresh 'EncryptionScheme' parameters should be generated for each key to
-- encrypt.
writeEncryptedKeyFile :: FilePath
                      -> EncryptionScheme -> ProtectionPassword -> X509.PrivKey
                      -> IO (Either StoreError ())
writeEncryptedKeyFile path alg pwd privKey =
    let pem = encryptKeyToPEM alg pwd privKey
     in either (return . Left) (fmap Right . writePEMs path . (:[])) pem

-- | Write a PKCS #8 encrypted private key to a bytearray in PEM format.
--
-- If multiple keys need to be stored in the same bytearray, use functions
-- 'encryptKeyToPEM' and 'pemWriteBS' or 'pemWriteLBS'.
--
-- Fresh 'EncryptionScheme' parameters should be generated for each key to
-- encrypt.
writeEncryptedKeyFileToMemory :: EncryptionScheme -> ProtectionPassword
                              -> X509.PrivKey -> Either StoreError B.ByteString
writeEncryptedKeyFileToMemory alg pwd privKey =
    pemWriteBS <$> encryptKeyToPEM alg pwd privKey

-- | Generate an unencrypted PEM for a private key.
keyToPEM :: PrivateKeyFormat -> X509.PrivKey -> PEM
keyToPEM TraditionalFormat = keyToTraditionalPEM
keyToPEM PKCS8Format       = keyToModernPEM

keyToTraditionalPEM :: X509.PrivKey -> PEM
keyToTraditionalPEM privKey =
    mkPEM (typeTag ++ " PRIVATE KEY") (encodeASN1S asn1)
  where (typeTag, asn1) = traditionalPrivKeyASN1S privKey

traditionalPrivKeyASN1S :: ASN1Elem e => X509.PrivKey -> (String, ASN1Stream e)
traditionalPrivKeyASN1S privKey =
    case privKey of
        X509.PrivKeyRSA k -> ("RSA", traditional k)
        X509.PrivKeyDSA k -> ("DSA", traditional (dsaPrivToPair k))
        X509.PrivKeyEC  k -> ("EC",  traditional k)
        X509.PrivKeyX25519  k -> ("X25519",  tradModern k)
        X509.PrivKeyX448    k -> ("X448",    tradModern k)
        X509.PrivKeyEd25519 k -> ("ED25519", tradModern k)
        X509.PrivKeyEd448   k -> ("ED448",   tradModern k)
  where
    traditional a = asn1s (Traditional a)
    tradModern a  = asn1s (Modern [] a)

keyToModernPEM :: X509.PrivKey -> PEM
keyToModernPEM privKey = mkPEM "PRIVATE KEY" (encodeASN1S asn1)
  where asn1 = modernPrivKeyASN1S [] privKey

modernPrivKeyASN1S :: forall e . ASN1Elem e => [Attribute] -> X509.PrivKey -> ASN1Stream e
modernPrivKeyASN1S attrs privKey =
    case privKey of
        X509.PrivKeyRSA k -> modern k
        X509.PrivKeyDSA k -> modern (dsaPrivToPair k)
        X509.PrivKeyEC  k -> modern k
        X509.PrivKeyX25519  k -> modern k
        X509.PrivKeyX448    k -> modern k
        X509.PrivKeyEd25519 k -> modern k
        X509.PrivKeyEd448   k -> modern k
  where
    modern :: forall a . ProduceASN1Object e (Modern a) => a -> ASN1Stream e
    modern a = asn1s (Modern attrs a)

-- | Generate a PKCS #8 encrypted PEM for a private key.
--
-- Fresh 'EncryptionScheme' parameters should be generated for each key to
-- encrypt.
encryptKeyToPEM :: EncryptionScheme -> ProtectionPassword -> X509.PrivKey
                -> Either StoreError PEM
encryptKeyToPEM alg pwd privKey = toPEM <$> encrypt alg pwd bs
  where bs = pemContent (keyToModernPEM privKey)
        toPEM pkcs8 = mkPEM "ENCRYPTED PRIVATE KEY" (encodeASN1Object pkcs8)

mkPEM :: String -> B.ByteString -> PEM
mkPEM name bs = PEM { pemName = name, pemHeader = [], pemContent = bs}


-- Private key formats: traditional (SSLeay compatible) and modern (PKCS #8)

-- | Private-key serialization format.
--
-- Encryption in traditional format is not supported currently.
data PrivateKeyFormat = TraditionalFormat -- ^ SSLeay compatible
                      | PKCS8Format       -- ^ PKCS #8
                      deriving (Show,Eq)

newtype Traditional a = Traditional { unTraditional :: a }

parseTraditional :: ParseASN1Object e (Traditional a) => ParseASN1 e a
parseTraditional = unTraditional <$> parse

data Modern a = Modern [Attribute] a

instance Functor Modern where
    fmap f (Modern attrs a) = Modern attrs (f a)

parseModern :: ParseASN1Object e (Modern a) => ParseASN1 e a
parseModern = unModern <$> parse
  where unModern (Modern _ a) = a

-- | A key associated with format.  Allows to implement 'ASN1Object' instances.
data FormattedKey a = FormattedKey PrivateKeyFormat a
    deriving (Show,Eq)

instance Functor FormattedKey where
    fmap f (FormattedKey fmt a) = FormattedKey fmt (f a)

instance (ProduceASN1Object e (Traditional a), ProduceASN1Object e (Modern a)) => ProduceASN1Object e (FormattedKey a) where
    asn1s (FormattedKey TraditionalFormat k) = asn1s (Traditional k)
    asn1s (FormattedKey PKCS8Format k)       = asn1s (Modern [] k)

instance (Monoid e, ParseASN1Object e (Traditional a), ParseASN1Object e (Modern a)) => ParseASN1Object e (FormattedKey a) where
    parse = (modern <$> parseModern) <|> (traditional <$> parseTraditional)
      where
        traditional = FormattedKey TraditionalFormat
        modern      = FormattedKey PKCS8Format

unFormat :: FormattedKey a -> a
unFormat (FormattedKey _ a) = a


-- Private Keys

instance ASN1Object (FormattedKey X509.PrivKey) where
    toASN1   = asn1s
    fromASN1 = runParseASN1State parse

instance ASN1Elem e => ProduceASN1Object e (Traditional X509.PrivKey) where
    asn1s (Traditional privKey) = snd $ traditionalPrivKeyASN1S privKey

instance Monoid e => ParseASN1Object e (Traditional X509.PrivKey) where
    parse = rsa <|> dsa <|> ecdsa
      where
        rsa   = Traditional . X509.PrivKeyRSA . unTraditional <$> parse
        dsa   = Traditional . X509.PrivKeyDSA . DSA.toPrivateKey . unTraditional <$> parse
        ecdsa = Traditional . X509.PrivKeyEC . unTraditional <$> parse

instance ASN1Elem e => ProduceASN1Object e (Modern X509.PrivKey) where
    asn1s (Modern attrs privKey) = modernPrivKeyASN1S attrs privKey

instance Monoid e => ParseASN1Object e (Modern X509.PrivKey) where
    parse = rsa <|> dsa <|> ecdsa <|> x25519 <|> x448 <|> ed25519 <|> ed448
      where
        rsa   = fmap X509.PrivKeyRSA  <$> parse
        dsa   = fmap (X509.PrivKeyDSA . DSA.toPrivateKey) <$> parse
        ecdsa = fmap X509.PrivKeyEC <$> parse
        x25519  = fmap X509.PrivKeyX25519 <$> parse
        x448    = fmap X509.PrivKeyX448 <$> parse
        ed25519 = fmap X509.PrivKeyEd25519 <$> parse
        ed448   = fmap X509.PrivKeyEd448 <$> parse

skipVersion :: Monoid e => ParseASN1 e ()
skipVersion = do
    IntVal v <- getNext
    when (v /= 0 && v /= 1) $
        throwParseError ("PKCS8: parsed invalid version: " ++ show v)

skipPublicKey :: Monoid e => ParseASN1 e ()
skipPublicKey = void (fmap Just parseTaggedPrimitive <|> return Nothing)
  where parseTaggedPrimitive = do { Other _ 1 bs <- getNext; return bs }

parseAttrKeys :: Monoid e => ParseASN1 e ([Attribute], B.ByteString)
parseAttrKeys = do
    OctetString bs <- getNext
    attrs <- parseAttributes (Container Context 0)
    skipPublicKey
    return (attrs, bs)


-- RSA

instance ASN1Object (FormattedKey RSA.PrivateKey) where
    toASN1   = asn1s
    fromASN1 = runParseASN1State parse

instance ASN1Elem e => ProduceASN1Object e (Traditional RSA.PrivateKey) where
    asn1s (Traditional privKey) =
        asn1Container Sequence (v . n . e . d . p1 . p2 . pexp1 . pexp2 . pcoef)
      where
        pubKey = RSA.private_pub privKey

        v     = gIntVal 0
        n     = gIntVal (RSA.public_n pubKey)
        e     = gIntVal (RSA.public_e pubKey)
        d     = gIntVal (RSA.private_d privKey)
        p1    = gIntVal (RSA.private_p privKey)
        p2    = gIntVal (RSA.private_q privKey)
        pexp1 = gIntVal (RSA.private_dP privKey)
        pexp2 = gIntVal (RSA.private_dQ privKey)
        pcoef = gIntVal (RSA.private_qinv privKey)

instance Monoid e => ParseASN1Object e (Traditional RSA.PrivateKey) where
    parse = onNextContainer Sequence $ do
        IntVal 0 <- getNext
        IntVal n <- getNext
        IntVal e <- getNext
        IntVal d <- getNext
        IntVal p1 <- getNext
        IntVal p2 <- getNext
        IntVal pexp1 <- getNext
        IntVal pexp2 <- getNext
        IntVal pcoef <- getNext
        let pubKey  = RSA.PublicKey { RSA.public_size = numBytes n
                                    , RSA.public_n    = n
                                    , RSA.public_e    = e
                                    }
            privKey = RSA.PrivateKey { RSA.private_pub  = pubKey
                                    , RSA.private_d    = d
                                    , RSA.private_p    = p1
                                    , RSA.private_q    = p2
                                    , RSA.private_dP   = pexp1
                                    , RSA.private_dQ   = pexp2
                                    , RSA.private_qinv = pcoef
                                    }
        return (Traditional privKey)

instance ASN1Elem e => ProduceASN1Object e (Modern RSA.PrivateKey) where
    asn1s (Modern attrs privKey) =
        asn1Container Sequence (v . alg . bs . att)
      where
        v     = gIntVal 0
        alg   = asn1Container Sequence (oid . gNull)
        oid   = gOID [1,2,840,113549,1,1,1]
        bs    = gOctetString (encodeASN1Object $ Traditional privKey)
        att   = attributesASN1S (Container Context 0) attrs

instance Monoid e => ParseASN1Object e (Modern RSA.PrivateKey) where
    parse = onNextContainer Sequence $ do
        skipVersion
        Null <- onNextContainer Sequence $ do
                    OID [1,2,840,113549,1,1,1] <- getNext
                    getNext
        (attrs, bs) <- parseAttrKeys
        let inner = decodeASN1' BER bs
            strError = Left .  ("PKCS8: error decoding inner RSA: " ++) . show
        case either strError (runParseASN1 parseTraditional) inner of
             Left err -> throwParseError ("PKCS8: error parsing inner RSA: " ++ err)
             Right privKey -> return (Modern attrs privKey)


-- DSA

instance ASN1Object (FormattedKey DSA.KeyPair) where
    toASN1   = asn1s
    fromASN1 = runParseASN1State parse

instance ASN1Elem e => ProduceASN1Object e (Traditional DSA.KeyPair) where
    asn1s (Traditional (DSA.KeyPair params pub priv)) =
        asn1Container Sequence (v . pqgASN1S params . pub' . priv')
      where
        v     = gIntVal 0
        pub'  = gIntVal pub
        priv' = gIntVal priv

instance Monoid e => ParseASN1Object e (Traditional DSA.KeyPair) where
    parse = onNextContainer Sequence $ do
        IntVal 0 <- getNext
        params <- parsePQG
        IntVal pub <- getNext
        IntVal priv <- getNext
        return (Traditional $ DSA.KeyPair params pub priv)

instance ASN1Elem e => ProduceASN1Object e (Modern DSA.KeyPair) where
    asn1s (Modern attrs (DSA.KeyPair params _ priv)) =
        asn1Container Sequence (v . alg . bs . att)
      where
        v     = gIntVal 0
        alg   = asn1Container Sequence (oid . pr)
        oid   = gOID [1,2,840,10040,4,1]
        pr    = asn1Container Sequence (pqgASN1S params)
        bs    = gOctetString (encodeASN1S $ gIntVal priv)
        att   = attributesASN1S (Container Context 0) attrs

instance Monoid e => ParseASN1Object e (Modern DSA.KeyPair) where
    parse = onNextContainer Sequence $ do
        skipVersion
        params <- onNextContainer Sequence $ do
                      OID [1,2,840,10040,4,1] <- getNext
                      onNextContainer Sequence parsePQG
        (attrs, bs) <- parseAttrKeys
        case decodeASN1' BER bs of
            Right [IntVal priv] ->
                let pub = DSA.calculatePublic params priv
                 in return (Modern attrs $ DSA.KeyPair params pub priv)
            Right _ -> throwParseError "PKCS8: invalid format when parsing inner DSA"
            Left  e -> throwParseError ("PKCS8: error parsing inner DSA: " ++ show e)

pqgASN1S :: ASN1Elem e => DSA.Params -> ASN1Stream e
pqgASN1S params = p . q . g
  where p = gIntVal (DSA.params_p params)
        q = gIntVal (DSA.params_q params)
        g = gIntVal (DSA.params_g params)

parsePQG :: Monoid e => ParseASN1 e DSA.Params
parsePQG = do
    IntVal p <- getNext
    IntVal q <- getNext
    IntVal g <- getNext
    return DSA.Params { DSA.params_p = p
                      , DSA.params_q = q
                      , DSA.params_g = g
                      }

dsaPrivToPair :: DSA.PrivateKey -> DSA.KeyPair
dsaPrivToPair k = DSA.KeyPair params pub x
  where pub     = DSA.calculatePublic params x
        params  = DSA.private_params k
        x       = DSA.private_x k


-- ECDSA

instance ASN1Object (FormattedKey X509.PrivKeyEC) where
    toASN1   = asn1s
    fromASN1 = runParseASN1State parse

instance ASN1Elem e => ProduceASN1Object e (Traditional X509.PrivKeyEC) where
    asn1s = innerEcdsaASN1S True . unTraditional

instance Monoid e => ParseASN1Object e (Traditional X509.PrivKeyEC) where
    parse = Traditional <$> parseInnerEcdsa Nothing

instance ASN1Elem e => ProduceASN1Object e (Modern X509.PrivKeyEC) where
    asn1s (Modern attrs privKey) = asn1Container Sequence (v . f . bs . att)
      where
        v     = gIntVal 0
        f     = asn1Container Sequence (oid . curveFnASN1S privKey)
        oid   = gOID [1,2,840,10045,2,1]
        bs    = gOctetString (encodeASN1S inner)
        inner = innerEcdsaASN1S False privKey
        att   = attributesASN1S (Container Context 0) attrs

instance Monoid e => ParseASN1Object e (Modern X509.PrivKeyEC) where
    parse = onNextContainer Sequence $ do
        skipVersion
        f <- onNextContainer Sequence $ do
            OID [1,2,840,10045,2,1] <- getNext
            parseCurveFn
        (attrs, bs) <- parseAttrKeys
        let inner = decodeASN1' BER bs
            strError = Left .  ("PKCS8: error decoding inner EC: " ++) . show
        case either strError (runParseASN1 $ parseInnerEcdsa $ Just f) inner of
            Left err -> throwParseError ("PKCS8: error parsing inner EC: " ++ err)
            Right privKey -> return (Modern attrs privKey)

innerEcdsaASN1S :: ASN1Elem e => Bool -> X509.PrivKeyEC -> ASN1Stream e
innerEcdsaASN1S addC k
    | addC      = asn1Container Sequence (v . ds . c0 . c1)
    | otherwise = asn1Container Sequence (v . ds . c1)
  where
    curve = fromMaybe (error "PKCS8: invalid EC parameters") (ecPrivKeyCurve k)
    bytes = curveOrderBytes curve

    v  = gIntVal 1
    ds = gOctetString (i2ospOf_ bytes (X509.privkeyEC_priv k))
    c0 = asn1Container (Container Context 0) (curveFnASN1S k)
    c1 = asn1Container (Container Context 1) pub

    pub = gBitString (toBitArray sp 0)
    X509.SerializedPoint sp = getSerializedPoint curve (X509.privkeyEC_priv k)

parseInnerEcdsa :: Monoid e
                => Maybe (ECDSA.PrivateNumber -> X509.PrivKeyEC)
                -> ParseASN1 e X509.PrivKeyEC
parseInnerEcdsa fn = onNextContainer Sequence $ do
    IntVal 1 <- getNext
    OctetString ds <- getNext
    let d = os2ip ds
    m <- onNextContainerMaybe (Container Context 0) parseCurveFn
    _ <- onNextContainerMaybe (Container Context 1) parsePK
    case fn <|> m of
        Nothing     -> throwParseError "PKCS8: no curve found in EC private key"
        Just getKey -> return (getKey d)
  where
    parsePK = do { BitString bs <- getNext; return bs }

curveFnASN1S :: ASN1Elem e => X509.PrivKeyEC -> ASN1Stream e
curveFnASN1S X509.PrivKeyEC_Named{..} = gOID (curveNameOID privkeyEC_name)
curveFnASN1S X509.PrivKeyEC_Prime{..} =
    asn1Container Sequence (v . prime . abSeed . gen . o . c)
  where
    X509.SerializedPoint generator = privkeyEC_generator
    bytes  = numBytes privkeyEC_prime

    v      = gIntVal 1

    prime  = asn1Container Sequence (oid . p)
    oid    = gOID [1,2,840,10045,1,1]
    p      = gIntVal privkeyEC_prime

    abSeed = asn1Container Sequence (a . b . seed)
    a      = gOctetString (i2ospOf_ bytes privkeyEC_a)
    b      = gOctetString (i2ospOf_ bytes privkeyEC_b)
    seed   = if privkeyEC_seed > 0
                 then gBitString (toBitArray (i2osp privkeyEC_seed) 0)
                 else id

    gen    = gOctetString generator
    o      = gIntVal privkeyEC_order
    c      = gIntVal privkeyEC_cofactor

parseCurveFn :: Monoid e => ParseASN1 e (ECDSA.PrivateNumber -> X509.PrivKeyEC)
parseCurveFn = parseNamedCurve <|> parsePrimeCurve
  where
    parseNamedCurve = do
        OID oid <- getNext
        case lookupCurveNameByOID oid of
            Just name -> return $ \d ->
                            X509.PrivKeyEC_Named
                                { X509.privkeyEC_name = name
                                , X509.privkeyEC_priv = d
                                }
            Nothing -> throwParseError ("PKCS8: unknown EC curve with OID " ++ show oid)

    parsePrimeCurve =
        onNextContainer Sequence $ do
            IntVal 1 <- getNext
            prime <- onNextContainer Sequence $ do
                OID [1,2,840,10045,1,1] <- getNext
                IntVal prime <- getNext
                return prime
            (a, b, seed) <- onNextContainer Sequence $ do
                OctetString a <- getNext
                OctetString b <- getNext
                seed <- parseOptionalSeed
                return (a, b, seed)
            OctetString generator <- getNext
            IntVal order <- getNext
            IntVal cofactor <- getNext
            return $ \d ->
                X509.PrivKeyEC_Prime
                    { X509.privkeyEC_priv      = d
                    , X509.privkeyEC_a         = os2ip a
                    , X509.privkeyEC_b         = os2ip b
                    , X509.privkeyEC_prime     = prime
                    , X509.privkeyEC_generator = X509.SerializedPoint generator
                    , X509.privkeyEC_order     = order
                    , X509.privkeyEC_cofactor  = cofactor
                    , X509.privkeyEC_seed      = seed
                    }

    parseOptionalSeed = do
        seedAvail <- hasNext
        if seedAvail
            then do BitString seed <- getNext
                    return (os2ip $ bitArrayGetData seed)
            else return 0


-- X25519, X448, Ed25519, Ed448

instance ASN1Elem e => ProduceASN1Object e (Modern X25519.SecretKey) where
    asn1s (Modern attrs privKey) = asn1Container Sequence (v . alg . bs . att)
      where
        v     = gIntVal 0
        alg   = asn1Container Sequence (gOID [1,3,101,110])
        bs    = innerEddsaASN1S privKey
        att   = attributesASN1S (Container Context 0) attrs

instance Monoid e => ParseASN1Object e (Modern X25519.SecretKey) where
    parse = onNextContainer Sequence $ do
        skipVersion
        onNextContainer Sequence $ do { OID [1,3,101,110] <- getNext; return () }
        (attrs, bs) <- parseAttrKeys
        Modern attrs <$> parseInnerEddsa "X25519" X25519.secretKey bs

instance ASN1Elem e => ProduceASN1Object e (Modern X448.SecretKey) where
    asn1s (Modern attrs privKey) = asn1Container Sequence (v . alg . bs . att)
      where
        v     = gIntVal 0
        alg   = asn1Container Sequence (gOID [1,3,101,111])
        bs    = innerEddsaASN1S privKey
        att   = attributesASN1S (Container Context 0) attrs

instance Monoid e => ParseASN1Object e (Modern X448.SecretKey) where
    parse = onNextContainer Sequence $ do
        skipVersion
        onNextContainer Sequence $ do { OID [1,3,101,111] <- getNext; return () }
        (attrs, bs) <- parseAttrKeys
        Modern attrs <$> parseInnerEddsa "X448" X448.secretKey bs

instance ASN1Elem e => ProduceASN1Object e (Modern Ed25519.SecretKey) where
    asn1s (Modern attrs privKey) = asn1Container Sequence (v . alg . bs . att)
      where
        v     = gIntVal 0
        alg   = asn1Container Sequence (gOID [1,3,101,112])
        bs    = innerEddsaASN1S privKey
        att   = attributesASN1S (Container Context 0) attrs

instance Monoid e => ParseASN1Object e (Modern Ed25519.SecretKey) where
    parse = onNextContainer Sequence $ do
        skipVersion
        onNextContainer Sequence $ do { OID [1,3,101,112] <- getNext; return () }
        (attrs, bs) <- parseAttrKeys
        Modern attrs <$> parseInnerEddsa "Ed25519" Ed25519.secretKey bs

instance ASN1Elem e => ProduceASN1Object e (Modern Ed448.SecretKey) where
    asn1s (Modern attrs privKey) = asn1Container Sequence (v . alg . bs . att)
      where
        v     = gIntVal 0
        alg   = asn1Container Sequence (gOID [1,3,101,113])
        bs    = innerEddsaASN1S privKey
        att   = attributesASN1S (Container Context 0) attrs

instance Monoid e => ParseASN1Object e (Modern Ed448.SecretKey) where
    parse = onNextContainer Sequence $ do
        skipVersion
        onNextContainer Sequence $ do { OID [1,3,101,113] <- getNext; return () }
        (attrs, bs) <- parseAttrKeys
        Modern attrs <$> parseInnerEddsa "Ed448" Ed448.secretKey bs

innerEddsaASN1S :: (ASN1Elem e, ByteArrayAccess key) => key -> ASN1Stream e
innerEddsaASN1S key = gOctetString (encodeASN1S inner)
  where inner = gOctetString (convert key)

parseInnerEddsa :: Monoid e
                => String
                -> (B.ByteString -> CryptoFailable key)
                -> B.ByteString
                -> ParseASN1 e key
parseInnerEddsa name buildKey input =
    case either strError (runParseASN1 parser) (decodeASN1' BER input) of
        Left err -> throwParseError ("PKCS8: error parsing inner " ++ name ++ ": " ++ err)
        Right privKey -> return privKey
  where
    innerMsg = "PKCS8: error decoding inner " ++ name ++ ": "
    strError = Left . (innerMsg ++) . show
    parser   = do
        OctetString bs <- getNext
        case buildKey bs of
            CryptoPassed privKey -> return privKey
            CryptoFailed _       ->
                throwParseError ("PKCS8: parsed invalid " ++ name ++ " secret key")
