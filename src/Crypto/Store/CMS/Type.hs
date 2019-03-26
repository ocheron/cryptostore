-- |
-- Module      : Crypto.Store.CMS.Type
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- CMS content information type.
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE TypeFamilies #-}
module Crypto.Store.CMS.Type
    ( ContentType(..)
    , Encap(..)
    , fromEncap
    ) where

import Data.ASN1.OID

import Crypto.Store.CMS.Util

-- | CMS content information type.
data ContentType = DataType              -- ^ Arbitrary octet string
                 | SignedDataType        -- ^ Signed content info
                 | EnvelopedDataType     -- ^ Enveloped content info
                 | DigestedDataType      -- ^ Content info with associated digest
                 | EncryptedDataType     -- ^ Encrypted content info
                 | AuthenticatedDataType -- ^ Authenticated content info
                 | AuthEnvelopedDataType -- ^ Authenticated-enveloped content info
                 deriving (Show,Eq)

instance Enumerable ContentType where
    values = [ DataType
             , SignedDataType
             , EnvelopedDataType
             , DigestedDataType
             , EncryptedDataType
             , AuthenticatedDataType
             , AuthEnvelopedDataType
             ]

instance OIDable ContentType where
    getObjectID DataType              = [1,2,840,113549,1,7,1]
    getObjectID SignedDataType        = [1,2,840,113549,1,7,2]
    getObjectID EnvelopedDataType     = [1,2,840,113549,1,7,3]
    getObjectID DigestedDataType      = [1,2,840,113549,1,7,5]
    getObjectID EncryptedDataType     = [1,2,840,113549,1,7,6]
    getObjectID AuthenticatedDataType = [1,2,840,113549,1,9,16,1,2]
    getObjectID AuthEnvelopedDataType = [1,2,840,113549,1,9,16,1,23]

instance OIDNameable ContentType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid

-- | Denote the state of encapsulated content in a CMS data structure.  This
-- type is isomorphic to 'Maybe'.
data Encap a
    = Detached    -- ^ Content is stored externally to the structure
    | Attached a  -- ^ Content is stored inside the CMS struture
    deriving (Show,Eq)

instance Functor Encap where
    fmap _ Detached = Detached
    fmap f (Attached c) = Attached (f c)

instance Applicative Encap where
    pure = Attached

    Attached f <*> e = fmap f e
    Detached   <*> _ = Detached

instance Foldable Encap where
    foldMap = fromEncap mempty

    foldr _ d Detached     = d
    foldr f d (Attached c) = f c d

    foldl _ d Detached     = d
    foldl f d (Attached c) = f d c

instance Traversable Encap where
    traverse _ Detached     = pure Detached
    traverse f (Attached c) = Attached <$> f c

-- | Fold over an 'Encap' value.  This is similar to function 'maybe'.  If the
-- content is detached, the first argument is returned.  Otherwise the second
-- argument is applied to the content.
fromEncap :: b -> (a -> b) -> Encap a -> b
fromEncap d _ Detached     = d
fromEncap _ f (Attached c) = f c
