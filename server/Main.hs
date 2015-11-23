{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import           Network.SSH.Keys
import           Network.SSH.Messages
import           Network.SSH.Packet ( SshIdent(..) )
import           Network.SSH.Server
import           Network.SSH.UserAuth

import           Control.Monad ( forever )
import           Control.Exception
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L
import           Network
                     ( PortID(..), HostName, PortNumber, withSocketsDo, listenOn
                     , accept, Socket )
import           System.Directory ( doesFileExist )
import           System.IO ( Handle, hClose )

import System.Posix.IO ( fdToHandle, closeFd )
import Control.Concurrent
import System.FilePath
import System.Environment
import System.Directory (getHomeDirectory)
import qualified SetGame
import qualified Graphics.Vty as Vty

import qualified Crypto.PubKey.RSA as RSA

import Openpty
import UnixTerminalFlags
import LoadKeys

main :: IO ()
main = withSocketsDo $
  do sock             <- listenOn (PortNumber 2200)
     (pubKey,privKey) <- loadKeys

     home    <- getHomeDirectory
     pubKeys <- loadPublicKeys (home </> ".ssh" </> "authorized_keys")
     user    <- getEnv "USER"
     let creds = [(S8.pack user,pubKeys)]

     -- Currently hardcoded kex algorithm
     let kex = ecdhSha2Nistp256
     -- let kex = diffieHellmanGroup14Sha1

     sshServer greeting kex privKey pubKey (mkServer creds sock)

greeting :: SshIdent
greeting  = SshIdent { sshProtoVersion    = "2.0"
                     , sshSoftwareVersion = "SSH_HaLVM_2.0"
                     , sshComments        = ""
                     }

mkServer :: Credentials -> Socket -> Server
mkServer creds sock = Server { sAccept = mkClient creds `fmap` accept sock }

convertWindowSize :: SshWindowSize -> Winsize
convertWindowSize winsize =
  Winsize
    { wsRow    = fromIntegral $ sshWsRows winsize
    , wsCol    = fromIntegral $ sshWsCols winsize
    , wsXPixel = fromIntegral $ sshWsX    winsize
    , wsYPixel = fromIntegral $ sshWsY    winsize
    }

type Credentials = [(S.ByteString, [SshPubCert])]

mkClient :: Credentials -> (Handle,HostName,PortNumber) -> Client
mkClient creds (h,_,_) = Client { .. }
  where
  cGet   = S.hGetSome h
  cPut   = L.hPutStr  h
  cClose =   hClose   h

  cOpenShell (term,winsize,termflags) eventChannel writeBytes =
    do (masterFd, slaveFd) <-
         openpty
           Nothing
           (Just (convertWindowSize winsize))
           (Just (foldl (\t (key,val) -> setTerminalFlag key val t) defaultTermios
                     termflags))

       masterH <- fdToHandle masterFd

       _ <- forkIO $
         forever (do out <- S.hGetSome masterH 1024
                     writeBytes (Just out)
                 ) `finally` writeBytes Nothing

       _ <- forkIO $
         let loop = do event <- readChan eventChannel
                       case event of
                         SessionClose ->
                           do closeFd masterFd
                              closeFd slaveFd
                         SessionWinsize winsize' ->
                           do changePtyWinsize masterFd (convertWindowSize winsize')
                              loop
                         SessionData bs ->
                           do S.hPut masterH bs
                              loop
         in loop

       let config = Vty.Config
                      { Vty.vmin     = Just 1
                      , Vty.vtime    = Just 100
                      , Vty.debugLog = Nothing
                      , Vty.inputMap = []
                      , Vty.inputFd  = Just slaveFd
                      , Vty.outputFd = Just slaveFd
                      , Vty.termName = Just (S8.unpack term)
                      }

       SetGame.gameMain config
       hClose masterH

  -- Querying for support
  cAuthHandler _ _ _ (SshAuthPublicKey alg key Nothing) =
    return (AuthPkOk alg key)

  cAuthHandler session_id username svc (SshAuthPublicKey alg key (Just sig)) =
    case lookup username creds of
      Just pubs
        | key `elem` pubs
        , verifyPubKeyAuthentication session_id username svc alg key sig
        -> return AuthAccepted
      _ -> return (AuthFailed ["publickey"])

  cAuthHandler _session_id user _svc m =
    do print (user,m)
       return (AuthFailed ["publickey"])

loadKeys :: IO (RSA.PublicKey, RSA.PrivateKey)
loadKeys  =
  do privExists <- doesFileExist "server.priv"
     pubExists  <- doesFileExist "server.pub"

     if privExists && pubExists
        then do pub  <- readFile "server.pub"
                priv <- readFile "server.priv"
                return (read pub, read priv) -- icky

        else do pair@(pub, priv) <- RSA.generate 256{-bytes-} 0x10001{-e-}
                writeFile "server.pub"  (show pub)
                writeFile "server.priv" (show priv)
                return pair
