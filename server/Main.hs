{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Network.SSH.Messages
import           Network.SSH.Packet ( SshIdent(..) )
import           Network.SSH.Server
import           Network.SSH.PubKey
import           Network.SSH.PrivateKeyFormat

import           Control.Monad
import           Control.Exception
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L
import           Network
                     ( PortID(..), HostName, PortNumber, withSocketsDo, listenOn
                     , accept, Socket )
import           System.IO ( Handle, hClose )
import           System.IO.Error ( isIllegalOperation )

import System.Posix.IO ( fdToHandle, closeFd )
import Control.Concurrent
import System.FilePath
import System.Environment
import System.Directory (getHomeDirectory)
import qualified SetGame
import qualified Graphics.Vty as Vty

import Openpty
import UnixTerminalFlags
import LoadKeys

main :: IO ()
main = withSocketsDo $
  do sock    <- listenOn (PortNumber 2200)
     sAuth   <- loadPrivateKeys "server_keys"

     home    <- getHomeDirectory
     pubKeys <- loadPublicKeys (home </> ".ssh" </> "authorized_keys")
     user    <- getEnv "USER"
     let creds = [(S8.pack user,pubKeys)]

     sshServer (mkServer sAuth creds sock)

greeting :: SshIdent
greeting  = SshIdent "SSH-2.0-SSH_HaLVM_2.0"

mkServer :: [ServerCredential] -> [ClientCredential] -> Socket -> Server
mkServer auths creds sock = Server
  { sAccept = mkClient creds `fmap` accept sock
  , sAuthenticationAlgs = auths
  , sIdent = greeting
  }

convertWindowSize :: SshWindowSize -> Winsize
convertWindowSize winsize =
  Winsize
    { wsRow    = fromIntegral $ sshWsRows winsize
    , wsCol    = fromIntegral $ sshWsCols winsize
    , wsXPixel = fromIntegral $ sshWsX    winsize
    , wsYPixel = fromIntegral $ sshWsY    winsize
    }

type ClientCredential = (S.ByteString, [SshPubCert])

mkClient :: [ClientCredential] -> (Handle,HostName,PortNumber) -> Client
mkClient creds (h,_,_) = Client { .. }
  where
  cGet   = S.hGetSome h
  cPut   = S.hPutStr  h . L.toStrict
  cClose =   hClose   h
  cLog   = putStrLn

  cDirectTcp _host _port _events _writeback = return False

  cRequestExec "echo" events writeback =
    do void (forkIO (echoServer events writeback))
       return True
  cRequestExec _command _events _writeback =
    return False

  -- Same as 'exec echo' above, which you access in OpenSSH by running
  -- @ssh <host> echo@. To access this "echo" subsystem in OpenSSH,
  -- use @ssh <host> -s echo@.
  cRequestSubsystem "echo" events writeback =
    do void (forkIO (echoServer events writeback))
       return True
  cRequestSubsystem _ _ _ = return False

  cOpenShell term winsize termflags eventChannel writeBytes =
    do (masterFd, slaveFd) <-
         openpty
           Nothing
           (Just (convertWindowSize winsize))
           (Just (foldl (\t (key,val) -> setTerminalFlag key val t) defaultTermios
                     termflags))

       masterH <- fdToHandle masterFd

       void $ forkIO $
         forever (do out <- S.hGetSome masterH 1024
                     writeBytes (Just out)
                 ) `finally` writeBytes Nothing
                   `catch` \e ->
                        unless (isIllegalOperation e) (throwIO e)

       void $ forkIO $
         let loop = do event <- readChan eventChannel
                       case event of
                         SessionEof -> loop
                         SessionClose -> closeFd slaveFd
                         SessionWinsize winsize' ->
                           do changePtyWinsize masterFd (convertWindowSize winsize')
                              loop
                         SessionData bs ->
                           do S.hPut masterH bs
                              loop
         in loop

       let config = Vty.Config
                      { Vty.vmin     = Just 1
                      , Vty.vtime    = Just 0
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

  cAuthHandler _ _ _ (SshAuthPassword "god" Nothing) =
    return AuthAccepted

  cAuthHandler session_id username svc (SshAuthPublicKey alg key (Just sig)) =
    case lookup username creds of
      Just pubs
        | key `elem` pubs
        , verifyPubKeyAuthentication session_id username svc alg key sig
        -> return AuthAccepted
      _ -> return (AuthFailed ["password","publickey"])

  cAuthHandler _session_id _user _svc _m =
       return (AuthFailed ["password","publickey"])

echoServer :: IO SessionEvent -> (Maybe S.ByteString -> IO ()) -> IO ()
echoServer read' write = loop
  where
  loop =
    do event <- read'
       case event of
         SessionData xs -> write (Just xs) >> loop
         SessionEof   -> write Nothing
         SessionClose -> return ()
         SessionWinsize{} -> loop
