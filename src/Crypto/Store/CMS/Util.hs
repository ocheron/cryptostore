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
    , lookupByOID
    , Enumerable(..)
    , OIDNameableWrapper(..)
    , withObjectID
    -- * Parsing ASN.1 objects
    , ParseASN1Object(..)
    -- * Algorithm Identifiers
    , AlgorithmId(..)
    , algorithmASN1S
    , algorithmMaybeASN1S
    , parseAlgorithm
    , parseAlgorithmMaybe
    -- * Miscellaneous functions
    , eqBA
    , orElse
    ) where

import           Data.ASN1.OID
import           Data.ASN1.Types
import qualified Data.ByteArray as B
import           Data.List (find)

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
             => String -> OID -> (a -> ParseASN1 b) -> ParseASN1 b
withObjectID name oid fn =
    case fromObjectID oid of
        Just val -> fn val
        Nothing  ->
            throwParseError ("Unsupported " ++ name ++ ": OID " ++ show oid)

-- | Types which can be parsed from ASN.1 and converted back to ASN.1 stream.
class ParseASN1Object obj where
    asn1s :: obj -> ASN1S
    parse :: ParseASN1 obj

instance ParseASN1Object obj => ParseASN1Object [obj] where
    asn1s l r = foldr asn1s r l
    parse = getMany parse

-- | Algorithm identifier with associated parameter.
class AlgorithmId param where
    type AlgorithmType param
    algorithmName  :: param -> String
    algorithmType  :: param -> AlgorithmType param
    parameterASN1S :: param -> ASN1S
    parseParameter :: AlgorithmType param -> ParseASN1 param

-- | Transform the algorithm identifier to ASN.1 stream.
algorithmASN1S :: (AlgorithmId param, OIDable (AlgorithmType param))
               => ASN1ConstructionType -> param -> ASN1S
algorithmASN1S ty p = asn1Container ty (oid . parameterASN1S p)
  where typ = algorithmType p
        oid = gOID (getObjectID typ)

-- | Transform the optional algorithm identifier to ASN.1 stream.
algorithmMaybeASN1S :: (AlgorithmId param, OIDable (AlgorithmType param))
                    => ASN1ConstructionType -> Maybe param -> ASN1S
algorithmMaybeASN1S _  Nothing  = id
algorithmMaybeASN1S ty (Just p) = algorithmASN1S ty p

-- | Parse an algorithm identifier from an ASN.1 stream.
parseAlgorithm :: forall param . (AlgorithmId param, OIDNameable (AlgorithmType param))
               => ASN1ConstructionType -> ParseASN1 param
parseAlgorithm ty = onNextContainer ty $ do
    OID oid <- getNext
    withObjectID (getName undefined) oid parseParameter
  where
    getName :: param -> String
    getName = algorithmName

-- | Parse an optional algorithm identifier from an ASN.1 stream.
parseAlgorithmMaybe :: forall param . (AlgorithmId param, OIDNameable (AlgorithmType param))
                    => ASN1ConstructionType -> ParseASN1 (Maybe param)
parseAlgorithmMaybe ty = onNextContainerMaybe ty $ do
    OID oid <- getNext
    withObjectID (getName undefined) oid parseParameter
  where
    getName :: param -> String
    getName = algorithmName

-- | Equality for heterogeneous bytearrays (not time-constant).
eqBA :: (B.ByteArrayAccess b1, B.ByteArrayAccess b2) => b1 -> b2 -> Bool
eqBA b1 b2 = and $ zipWith (==) (B.unpack b1) (B.unpack b2)

-- | Execute the second action only if the first action produced 'Nothing'.
orElse :: Monad m => m (Maybe a) -> m (Maybe a) -> m (Maybe a)
orElse pa pb = do
    va <- pa
    case va of
        Nothing -> pb
        _       -> return va
