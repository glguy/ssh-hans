{-# LANGUAGE RecordWildCards #-}

module Main where

import           Network.SSH.Server

import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import           Network
                     ( PortID(..), HostName, PortNumber, withSocketsDo, listenOn
                     , accept, Socket )
import           System.Directory ( doesFileExist )
import           System.IO ( Handle, hClose )


main :: IO ()
main  = withSocketsDo $
  do sock             <- listenOn (PortNumber 2200)
     (privKey,pubKey) <- loadKeys
     sshServer privKey pubKey (mkServer sock)

mkServer :: Socket -> Server
mkServer sock = Server { sAccept = mkClient `fmap` accept sock }

mkClient :: (Handle,HostName,PortNumber) -> Client
mkClient (h,_,_) = Client { .. }
  where
  cGet   = S.hGetSome h
  cPut   = L.hPutStr  h
  cClose =   hClose   h

  cAuthHandler = \ user m -> do print (user,m)
                                return False

loadKeys :: IO (PrivateKey, PublicKey)
loadKeys  =
  do privExists <- doesFileExist "server.priv"
     pubExists  <- doesFileExist "server.pub"

     if privExists && pubExists
        then do priv <- readFile "server.priv"
                pub  <- readFile "server.pub"
                return (read priv, read pub) -- icky

        else genKeyPair
