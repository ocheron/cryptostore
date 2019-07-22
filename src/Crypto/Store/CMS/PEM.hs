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
    , berToContentInfo
    , pemToContentInfo
    , writeCMSFile
    , writeCMSFileToMemory
    , contentInfoToDER
    , contentInfoToPEM
    ) where

import qualified Data.ByteString as B
import           Data.Maybe (catMaybes)

import Crypto.Store.CMS.Info
import Crypto.Store.CMS.Util
import Crypto.Store.Error
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

-- | Read a content info from a bytearray in BER format.
berToContentInfo :: B.ByteString -> Either StoreError ContentInfo
berToContentInfo = decodeASN1Object

-- | Read a content info from a 'PEM' element and add it to the accumulator
-- list.
pemToContentInfo :: [Maybe ContentInfo] -> PEM -> [Maybe ContentInfo]
pemToContentInfo acc pem
    | pemName pem `elem` names = decode (pemContent pem)
    | otherwise                = Nothing : acc
  where
    names = [ "CMS", "PKCS7" ]
    decode bs =
        case berToContentInfo bs of
            Left _ -> Nothing : acc
            Right info -> Just info : acc


-- Writing to PEM format

-- | Write content info elements to a PEM file.
writeCMSFile :: FilePath -> [ContentInfo] -> IO ()
writeCMSFile path = B.writeFile path . writeCMSFileToMemory

-- | Write content info elements to a bytearray in PEM format.
writeCMSFileToMemory :: [ContentInfo] -> B.ByteString
writeCMSFileToMemory = pemsWriteBS . map contentInfoToPEM

-- | Generate a bytearray in DER format for a content info.
contentInfoToDER :: ContentInfo -> B.ByteString
contentInfoToDER = encodeASN1Object

-- | Generate PEM for a content info.
contentInfoToPEM :: ContentInfo -> PEM
contentInfoToPEM info = PEM { pemName = "CMS", pemHeader = [], pemContent = bs}
  where bs = contentInfoToDER info
