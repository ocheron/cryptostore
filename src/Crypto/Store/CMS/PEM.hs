-- |
-- Module      : Crypto.Store.CMS.PEM
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- PEM serialization and deserialization of CMS 'ContentInfo'.
module Crypto.Store.CMS.PEM
    ( readCMSFile
    , readCMSFileFromMemory
    , pemToContentInfo
    , writeCMSFile
    , writeCMSFileToMemory
    , contentInfoToPEM
    ) where

import           Data.ASN1.BinaryEncoding
import           Data.ASN1.Encoding
import           Data.ASN1.Types
import qualified Data.ByteString as B
import           Data.Maybe (catMaybes)

import Crypto.Store.CMS.Info
import Crypto.Store.CMS.Util
import Crypto.Store.PEM


-- Reading from PEM format

-- | Read content info elements from a PEM file.
readCMSFile :: FilePath -> IO [ContentInfo]
readCMSFile path = accumulate <$> readPEMs path

-- | Read content info elements from a bytearray in PEM format.
readCMSFileFromMemory :: B.ByteString -> [ContentInfo]
readCMSFileFromMemory = either (const []) accumulate . pemParseBS

accumulate :: [PEM] -> [ContentInfo]
accumulate = catMaybes . foldr (flip pemToContentInfo) []

-- | Read a content info from a 'PEM' element and add it to the accumulator
-- list.
pemToContentInfo :: [Maybe ContentInfo] -> PEM -> [Maybe ContentInfo]
pemToContentInfo acc pem
    | pemName pem `elem` names = decode (pemContent pem)
    | otherwise                = Nothing : acc
  where
    names = [ "CMS", "PKCS7" ]
    decode bs =
        case decodeASN1' BER bs of
            Left _ -> Nothing : acc
            Right asn1 ->
                case fromASN1 asn1 of
                    Right (info, []) -> Just info : acc
                    _                -> Nothing : acc


-- Writing to PEM format

-- | Write content info elements to a PEM file.
writeCMSFile :: FilePath -> [ContentInfo] -> IO ()
writeCMSFile path = B.writeFile path . writeCMSFileToMemory

-- | Write content info elements to a bytearray in PEM format.
writeCMSFileToMemory :: [ContentInfo] -> B.ByteString
writeCMSFileToMemory = pemsWriteBS . map contentInfoToPEM

-- | Generate PEM for a content info.
contentInfoToPEM :: ContentInfo -> PEM
contentInfoToPEM info = PEM { pemName = "CMS", pemHeader = [], pemContent = bs}
  where bs = encodeASN1Object info
