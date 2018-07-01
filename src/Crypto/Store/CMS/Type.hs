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
    ) where

import Data.ASN1.OID

import Crypto.Store.CMS.Util

-- | CMS content information type.
data ContentType = DataType              -- ^ Arbitrary octet string
                 | EnvelopedDataType     -- ^ Enveloped content info
                 | DigestedDataType      -- ^ Content info with associated digest
                 | EncryptedDataType     -- ^ Encrypted content info
                 deriving (Show,Eq)

instance Enumerable ContentType where
    values = [ DataType
             , EnvelopedDataType
             , DigestedDataType
             , EncryptedDataType
             ]

instance OIDable ContentType where
    getObjectID DataType              = [1,2,840,113549,1,7,1]
    getObjectID EnvelopedDataType     = [1,2,840,113549,1,7,3]
    getObjectID DigestedDataType      = [1,2,840,113549,1,7,5]
    getObjectID EncryptedDataType     = [1,2,840,113549,1,7,6]

instance OIDNameable ContentType where
    fromObjectID oid = unOIDNW <$> fromObjectID oid
