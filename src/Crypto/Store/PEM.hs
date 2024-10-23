-- |
-- Module      : Crypto.Store.PEM
-- License     : BSD-style
-- Maintainer  : Olivier Chéron <olivier.cheron@gmail.com>
-- Stability   : experimental
-- Portability : unknown
--
-- Extend module "Data.PEM".
module Crypto.Store.PEM
    ( readPEMs
    , writePEMs
    , pemsWriteBS
    , pemsWriteLBS
    , mkPEM
    , module Data.PEM
    ) where

import Data.PEM
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

-- | Read a PEM file from disk.
readPEMs :: FilePath -> IO [PEM]
readPEMs filepath = either error id . pemParseLBS <$> L.readFile filepath

-- | Convert a list of PEM elements to a bytestring.
pemsWriteBS :: [PEM] -> B.ByteString
pemsWriteBS = L.toStrict . pemsWriteLBS

-- | Convert a list of PEM elements to a lazy bytestring.
pemsWriteLBS :: [PEM] -> L.ByteString
pemsWriteLBS = L.concat . map pemWriteLBS

-- | Write a PEM file to disk.
writePEMs :: FilePath -> [PEM] -> IO ()
writePEMs filepath = L.writeFile filepath . pemsWriteLBS

-- | Make a PEM without headers.
mkPEM :: String -> B.ByteString -> PEM
mkPEM name bs = PEM { pemName = name, pemHeader = [], pemContent = bs}
