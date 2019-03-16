-- |
-- Module      : Crypto.Store.CMS.Digested
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
--
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Store.CMS.Digested
    ( DigestedData(..)
    ) where

import Control.Monad

import           Data.ASN1.Types
import qualified Data.ByteArray as B

import Crypto.Hash hiding (MD5)

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Signed
import Crypto.Store.CMS.Type
import Crypto.Store.CMS.Util

-- | Digested content information.
data DigestedData content = forall hashAlg. HashAlgorithm hashAlg => DigestedData
    { ddDigestAlgorithm :: DigestProxy hashAlg     -- ^ Digest algorithm
    , ddContentType :: ContentType                 -- ^ Inner content type
    , ddEncapsulatedContent :: content             -- ^ Encapsulated content
    , ddDigest :: Digest hashAlg                   -- ^ Digest value
    }

instance Show content => Show (DigestedData content) where
    showsPrec d DigestedData{..} = showParen (d > 10) $
        showString "DigestedData "
            . showString "{ ddDigestAlgorithm = " . shows ddDigestAlgorithm
            . showString ", ddContentType = " . shows ddContentType
            . showString ", ddEncapsulatedContent = " . shows ddEncapsulatedContent
            . showString ", ddDigest = " . shows ddDigest
            . showString " }"

instance Eq content => Eq (DigestedData content) where
    DigestedData a1 t1 e1 d1 == DigestedData a2 t2 e2 d2 =
        DigestAlgorithm a1 == DigestAlgorithm a2 && d1 `B.eq` d2 && t1 == t2 && e1 == e2

instance ASN1Elem e => ProduceASN1Object e (DigestedData (Encap EncapsulatedContent)) where
    asn1s DigestedData{..} =
        asn1Container Sequence (ver . alg . ci . dig)
      where
        v = if ddContentType == DataType then 0 else 2
        d = DigestAlgorithm ddDigestAlgorithm

        ver = gIntVal v
        alg = algorithmASN1S Sequence d
        ci  = encapsulatedContentInfoASN1S ddContentType ddEncapsulatedContent
        dig = gOctetString (B.convert ddDigest)

instance Monoid e => ParseASN1Object e (DigestedData (Encap EncapsulatedContent)) where
    parse =
        onNextContainer Sequence $ do
            IntVal v <- getNext
            when (v /= 0 && v /= 2) $
                throwParseError ("DigestedData: parsed invalid version: " ++ show v)
            alg <- parseAlgorithm Sequence
            (ct, bs) <- parseEncapsulatedContentInfo
            OctetString digValue <- getNext
            case alg of
                DigestAlgorithm digAlg ->
                    case digestFromByteString digValue of
                        Nothing -> throwParseError "DigestedData: parsed invalid digest"
                        Just d  ->
                            return DigestedData { ddDigestAlgorithm = digAlg
                                                , ddContentType = ct
                                                , ddEncapsulatedContent = bs
                                                , ddDigest = d
                                                }
