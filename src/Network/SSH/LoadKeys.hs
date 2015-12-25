{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.LoadKeys where

import           Control.Monad (unless)
import           Data.ByteArray.Encoding (Base(Base64), convertFromBase)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import           Data.Serialize (runGet)

import           Network.SSH.Messages

loadPublicKeys :: FilePath -> IO [SshPubCert]
loadPublicKeys fp =
  do keys <- B.readFile fp
     return [ key | line <- B8.lines keys
                  , key  <- case decodePublicKey line of
                              Right k -> [k]
                              Left  _ -> []
                  ]

decodePublicKey :: ByteString -> Either String SshPubCert
decodePublicKey xs =
  do (keyType, encoded) <- case B8.words xs of
                             x:y:_ -> return (x,y)
                             _     -> Left "Bad outer format"
     decoded <- convertFromBase Base64 encoded
     pubCert <- runGet getSshPubCert decoded
     unless (keyType == sshPubCertName pubCert) (Left "Mismatched key type")
     return pubCert
