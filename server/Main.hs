{-# LANGUAGE RecordWildCards #-}

module Main where

import           Network.SSH.Server

import           Codec.Crypto.RSA.Exceptions ( generateKeyPair, generatePQ )
import           Crypto.Classes.Exceptions ( newGenIO )
import           Crypto.Random.DRBG ( CtrDRBG )
import           Crypto.Types.PubKey.RSA ( PublicKey(..), PrivateKey(..) )
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

loadKeys :: IO (PrivateKey, PublicKey)
loadKeys  =
  do gen <- newGenIO

     privExists <- doesFileExist "server.priv"
     pubExists  <- doesFileExist "server.pub"

     if privExists && pubExists
        then do priv <- readFile "server.priv"
                pub  <- readFile "server.pub"
                return (read priv, read pub) -- icky

        else do let (pub,priv,_) = generateKeyPair (gen :: CtrDRBG) 1024
                    (p,q,_)      = generatePQ gen (1024 `div` 8)
                    priv'        = priv { private_p = p, private_q = q }
                writeFile "server.priv" (show priv')
                writeFile "server.pub"  (show pub)
                return (priv', pub)
