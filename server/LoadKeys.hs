{-# LANGUAGE OverloadedStrings #-}

module LoadKeys where

import Control.Monad (unless)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import Data.Serialize (runGet)

import Network.SSH.Messages

loadPublicKey :: FilePath -> IO (Either String SshPubCert)
loadPublicKey = fmap decodePublicKey . B.readFile

decodePublicKey :: ByteString -> Either String SshPubCert
decodePublicKey xs =
  do (keyType, encoded) <- case B8.words xs of
                             x:y:_ -> return (x,y)
                             _     -> Left "Bad outer format"
     decoded <- Base64.decode encoded
     pubCert <- runGet getSshPubCert decoded
     unless (keyType == sshPubCertName pubCert) (Left "Mismatched key type")
     return pubCert
