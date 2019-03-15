-- |
-- Module      : Crypto.Store.CMS.Authenticated
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
--
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE RecordWildCards #-}
module Crypto.Store.CMS.Authenticated
    ( AuthenticatedData(..)
    ) where

import Control.Applicative
import Control.Monad

import           Data.ASN1.Types
import qualified Data.ByteArray as B

import Crypto.Cipher.Types

import Crypto.Store.ASN1.Generate
import Crypto.Store.ASN1.Parse
import Crypto.Store.CMS.Algorithms
import Crypto.Store.CMS.Attribute
import Crypto.Store.CMS.Enveloped
import Crypto.Store.CMS.OriginatorInfo
import Crypto.Store.CMS.Signed
import Crypto.Store.CMS.Type
import Crypto.Store.CMS.Util

-- | Authenticated content information.
data AuthenticatedData = AuthenticatedData
    { adOriginatorInfo :: OriginatorInfo
      -- ^ Optional information about the originator
    , adRecipientInfos :: [RecipientInfo]
      -- ^ Information for recipients, allowing to authenticate the content
    , adMACAlgorithm :: MACAlgorithm
      -- ^ MAC algorithm
    , adDigestAlgorithm :: Maybe DigestAlgorithm
      -- ^ Optional digest algorithm
    , adContentType :: ContentType
      -- ^ Inner content type
    , adEncapsulatedContent :: EncapsulatedContent
      -- ^ Encapsulated content
    , adAuthAttrs :: [Attribute]
      -- ^ Optional authenticated attributes
    , adMAC :: MessageAuthenticationCode
      -- ^ Message authentication code
    , adUnauthAttrs :: [Attribute]
      -- ^ Optional unauthenticated attributes
    }
    deriving (Show,Eq)

instance ProduceASN1Object ASN1P AuthenticatedData where
    asn1s AuthenticatedData{..} =
        asn1Container Sequence (ver . oi . ris . alg . dig . ci . aa . tag . ua)
      where
        ver = gIntVal v
        ris = asn1Container Set (asn1s adRecipientInfos)
        alg = algorithmASN1S Sequence adMACAlgorithm
        dig = algorithmMaybeASN1S (Container Context 1) adDigestAlgorithm
        ci  = encapsulatedContentInfoASN1S adContentType adEncapsulatedContent
        aa  = attributesASN1S(Container Context 2) adAuthAttrs
        tag = gOctetString (B.convert adMAC)
        ua  = attributesASN1S (Container Context 3) adUnauthAttrs

        oi | adOriginatorInfo == mempty = id
           | otherwise = originatorInfoASN1S (Container Context 0) adOriginatorInfo

        v | hasChoiceOther adOriginatorInfo = 3
          | otherwise                       = 0

instance ParseASN1Object [ASN1Event] AuthenticatedData where
    parse =
        onNextContainer Sequence $ do
            IntVal v <- getNext
            when (v `notElem` [0, 1, 3]) $
                throwParseError ("AuthenticatedData: parsed invalid version: " ++ show v)
            oi <- parseOriginatorInfo (Container Context 0) <|> return mempty
            ris <- onNextContainer Set parse
            alg <- parseAlgorithm Sequence
            dig <- parseAlgorithmMaybe (Container Context 1)
            (ct, bs) <- parseEncapsulatedContentInfo
            aAttrs <- parseAttributes (Container Context 2)
            OctetString tag <- getNext
            uAttrs <- parseAttributes (Container Context 3)
            return AuthenticatedData { adOriginatorInfo = oi
                                     , adRecipientInfos = ris
                                     , adMACAlgorithm = alg
                                     , adDigestAlgorithm = dig
                                     , adContentType = ct
                                     , adEncapsulatedContent = bs
                                     , adAuthAttrs = aAttrs
                                     , adMAC = AuthTag $ B.convert tag
                                     , adUnauthAttrs = uAttrs
                                     }
