-- |
-- Module      : Crypto.Store.CMS.Util
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- CMS and ASN.1 utilities
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeFamilies #-}
{-# LANGUAGE UndecidableInstances #-}
module Crypto.Store.CMS.Util
    (
    -- * Testing ASN.1 types
      nullOrNothing
    , intOrNothing
    , dateTimeOrNothing
    -- * Object Identifiers
    , OIDTable
    , lookupOID
    , Enumerable(..)
    , OIDNameableWrapper(..)
    , withObjectID
    -- * Parsing and encoding ASN.1 objects
    , ASN1Event
    , ASN1ObjectExact(..)
    , ProduceASN1Object(..)
    , encodeASN1Object
    , ParseASN1Object(..)
    , fromASN1Repr
    -- * Algorithm Identifiers
    , AlgorithmId(..)
    , algorithmASN1S
    , algorithmMaybeASN1S
    , parseAlgorithm
    , parseAlgorithmMaybe
    -- * Miscellaneous functions
    , orElse
    ) where

import           Data.ASN1.BinaryEncoding.Raw
import           Data.ASN1.OID
import           Data.ASN1.Stream
import           Data.ASN1.Types
import           Data.ByteString (ByteString)
import           Data.List (find)
import           Data.X509

import Time.Types (DateTime)

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse

-- | Try to parse a 'Null' ASN.1 value.
nullOrNothing :: ASN1 -> Maybe ()
nullOrNothing Null = Just ()
nullOrNothing _    = Nothing

-- | Try to parse an 'IntVal' ASN.1 value.
intOrNothing :: ASN1 -> Maybe Integer
intOrNothing (IntVal i) = Just i
intOrNothing _          = Nothing

-- | Try to parse a 'DateTime' ASN.1 value.
dateTimeOrNothing :: ASN1 -> Maybe DateTime
dateTimeOrNothing (ASN1Time _ t _) = Just t
dateTimeOrNothing _                = Nothing

-- | Mapping between values and OIDs.
type OIDTable a = [(a, OID)]

-- | Find the value associated to an OID.
lookupByOID :: OIDTable a -> OID -> Maybe a
lookupByOID table oid = fst <$> find ((==) oid . snd) table

-- | Find the OID associated to a value.
lookupOID :: Eq a => OIDTable a -> a -> Maybe OID
lookupOID table a = lookup a table

-- | Types with a finite set of values.
class Enumerable a where
    -- | Return all possible values for the given type.
    values :: [a]

-- | Type used to transform a 'Enumerable' instance to an 'OIDNameable'
-- instance.
newtype OIDNameableWrapper a = OIDNW { unOIDNW :: a }
    deriving (Show,Eq)

instance (Enumerable a, OIDable a) => OIDNameable (OIDNameableWrapper a) where
    fromObjectID = lookupByOID table
      where table = [ (OIDNW val, getObjectID val) | val <- values ]

-- | Convert the specified OID and apply a parser to the result.
withObjectID :: OIDNameable a
             => String -> OID -> (a -> ParseASN1 e b) -> ParseASN1 e b
withObjectID name oid fn =
    case fromObjectID oid of
        Just val -> fn val
        Nothing  ->
            throwParseError ("Unsupported " ++ name ++ ": OID " ++ show oid)

-- | Objects that can produce an ASN.1 stream.
class ProduceASN1Object e obj where
    asn1s :: obj -> ASN1Stream e

instance ProduceASN1Object e obj => ProduceASN1Object e [obj] where
    asn1s l r = foldr asn1s r l

instance ASN1Elem e => ProduceASN1Object e DistinguishedName where
    asn1s = asn1Container Sequence . inner
      where
        inner (DistinguishedName dn) cont = foldr dnSet cont dn
        dnSet (oid, cs) =
            asn1Container Set $
                asn1Container Sequence (gOID oid . gASN1String cs)

instance (Show a, Eq a, ASN1Object a) => ProduceASN1Object ASN1P (SignedExact a) where
    asn1s = gEncoded . encodeSignedObject

-- | Encode the ASN.1 object to DER format.
encodeASN1Object :: ProduceASN1Object ASN1P obj => obj -> ByteString
encodeASN1Object = encodeASN1S . asn1s

-- | Objects that can be parsed from an ASN.1 stream.
class Monoid e => ParseASN1Object e obj where
    parse :: ParseASN1 e obj

instance ParseASN1Object e obj => ParseASN1Object e [obj] where
    parse = getMany parse

instance Monoid e => ParseASN1Object e DistinguishedName where
    parse = DistinguishedName <$> onNextContainer Sequence inner
      where
        inner = concat <$> getMany parseOne
        parseOne =
            onNextContainer Set $ getMany $
                onNextContainer Sequence $ do
                    OID oid <- getNext
                    ASN1String cs <- getNext
                    return (oid, cs)

instance (Show a, Eq a, ASN1Object a) => ParseASN1Object [ASN1Event] (SignedExact a) where
    parse = withAnnotations parseSequence >>= finish
      where
        parseSequence = onNextContainer Sequence (getMany getNext)
        finish (_, events) =
            case decodeSignedObject (toByteString events) of
                Right se -> return se
                Left err -> throwParseError ("SignedExact: " ++ err)

-- | Create an object from the ASN.1 stream.
fromASN1Repr :: ParseASN1Object [ASN1Event] obj
             => [ASN1Repr] -> Either String (obj, [ASN1Repr])
fromASN1Repr = runParseASN1State_ parse

-- | An ASN.1 object associated with the raw data it was parsed from.
data ASN1ObjectExact a = ASN1ObjectExact
    { exactObject    :: a           -- ^ The wrapped ASN.1 object
    , exactObjectRaw :: ByteString  -- ^ The raw representation of this object
    } deriving Show

instance Eq a => Eq (ASN1ObjectExact a)
    where a == b = exactObject a == exactObject b

instance ProduceASN1Object ASN1P a => ProduceASN1Object ASN1P (ASN1ObjectExact a) where
    asn1s = gEncoded . exactObjectRaw

instance ParseASN1Object [ASN1Event] a => ParseASN1Object [ASN1Event] (ASN1ObjectExact a) where
    parse = do
        (obj, events) <- withAnnotations parse
        let objRaw = toByteString events
        return ASN1ObjectExact { exactObject = obj, exactObjectRaw = objRaw }

-- | Algorithm identifier with associated parameter.
class AlgorithmId param where
    type AlgorithmType param
    algorithmName  :: param -> String
    algorithmType  :: param -> AlgorithmType param
    parameterASN1S :: ASN1Elem e => param -> ASN1Stream e
    parseParameter :: Monoid e => AlgorithmType param -> ParseASN1 e param

-- | Transform the algorithm identifier to ASN.1 stream.
algorithmASN1S :: (ASN1Elem e, AlgorithmId param, OIDable (AlgorithmType param))
               => ASN1ConstructionType -> param -> ASN1Stream e
algorithmASN1S ty p = asn1Container ty (oid . parameterASN1S p)
  where typ = algorithmType p
        oid = gOID (getObjectID typ)

-- | Transform the optional algorithm identifier to ASN.1 stream.
algorithmMaybeASN1S :: (ASN1Elem e, AlgorithmId param, OIDable (AlgorithmType param))
                    => ASN1ConstructionType -> Maybe param -> ASN1Stream e
algorithmMaybeASN1S _  Nothing  = id
algorithmMaybeASN1S ty (Just p) = algorithmASN1S ty p

-- | Parse an algorithm identifier from an ASN.1 stream.
parseAlgorithm :: forall e param . (Monoid e, AlgorithmId param, OIDNameable (AlgorithmType param))
               => ASN1ConstructionType -> ParseASN1 e param
parseAlgorithm ty = onNextContainer ty $ do
    OID oid <- getNext
    withObjectID (getName undefined) oid parseParameter
  where
    getName :: param -> String
    getName = algorithmName

-- | Parse an optional algorithm identifier from an ASN.1 stream.
parseAlgorithmMaybe :: forall e param . (Monoid e, AlgorithmId param, OIDNameable (AlgorithmType param))
                    => ASN1ConstructionType -> ParseASN1 e (Maybe param)
parseAlgorithmMaybe ty = onNextContainerMaybe ty $ do
    OID oid <- getNext
    withObjectID (getName undefined) oid parseParameter
  where
    getName :: param -> String
    getName = algorithmName

-- | Execute the second action only if the first action produced 'Nothing'.
orElse :: Monad m => m (Maybe a) -> m (Maybe a) -> m (Maybe a)
orElse pa pb = do
    va <- pa
    case va of
        Nothing -> pb
        _       -> return va
