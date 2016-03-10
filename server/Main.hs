{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Network.SSH.LoadKeys
import           Network.SSH.Messages
import           Network.SSH.Server

import           Control.Monad
import           Control.Exception
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import           Network
                     ( PortID(..), withSocketsDo, listenOn
                     , accept, Socket )
import           System.IO ( hClose )
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

main :: IO ()
main = withSocketsDo $
  do args <- getArgs
     let port = case args of
          [portString] -> fromInteger $ read portString
          _            -> error "usage: server LISTEN_PORT"
     sock    <- listenOn (PortNumber port)
     sAuth   <- loadPrivateKeys "server_keys"

     home    <- getHomeDirectory
     user    <- getEnv "USER"
     let pubKeys = [home </> ".ssh" </> "authorized_keys"]
     let creds   = [(S8.pack user,pubKeys)]
     let debugLevel = 1

     sshServer (mkServer debugLevel sAuth creds sock)

mkServer :: Int -> [ServerCredential] -> [ClientCredential] -> Socket -> Server
mkServer debugLevel auths creds sock = Server
  { sAccept = do
      (handle',_,_) <- accept sock
      let h = handle2HandleLike handle'
      let sh = mkSessionHandlers creds
      return (sh, h)
  , sAuthenticationAlgs = auths
  , sVersion = "SSH_HaLVM_2.0"
  , sDebugLevel = debugLevel
  }

convertWindowSize :: SshWindowSize -> Winsize
convertWindowSize winsize =
  Winsize
    { wsRow    = fromIntegral $ sshWsRows winsize
    , wsCol    = fromIntegral $ sshWsCols winsize
    , wsXPixel = fromIntegral $ sshWsX    winsize
    , wsYPixel = fromIntegral $ sshWsY    winsize
    }

type ClientCredential = (S.ByteString, [FilePath])

mkSessionHandlers :: [ClientCredential] -> SessionHandlers
mkSessionHandlers creds = SessionHandlers { .. }
  where
  cDirectTcp _host _port _events _writeback = return False

  cRequestExec "echo" events writeback =
    do void (forkIO (echoServer events writeback))
       return True
  cRequestExec _command _events _writeback =
    return False

  -- Same as 'exec echo' above, which you access in OpenSSH by running
  -- @ssh <host> echo@. To access this "echo" subsystem in OpenSSH,
  -- use @ssh <host> -s echo@.
  cRequestSubsystem "echo" readEvent writeback =
    do void (forkIO (echoServer readEvent writeback))
       return True
  cRequestSubsystem _ _ _ = return False

  cOpenShell term winsize termflags readEvent writeBytes =
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
         let loop = do event <- readEvent
                       case event of
                         SessionEof -> loop
                         SessionClose -> closeFd slaveFd
                         SessionWinsize winsize' ->
                           do changePtyWinsize masterFd (convertWindowSize winsize')
                              loop
                         SessionData bs ->
                           do S.hPut masterH bs
                              loop
                         SessionRequestResponse{} -> loop
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

       void $ forkIO $ do
         SetGame.gameMain config
         hClose masterH

       return True

  cAuthHandler = defaultAuthHandler
    (defaultCheckPw (const $ Just "god"))
    (defaultLookupPubKeys (\user -> return $ maybe [] id $ lookup user creds))

echoServer :: IO SessionEvent -> (Maybe S.ByteString -> IO ()) -> IO ()
echoServer readEvent write = loop
  where
  loop =
    do event <- readEvent
       case event of
         SessionData xs   -> write (Just xs) >> loop
         SessionEof       -> write Nothing
         SessionClose     -> return ()
         SessionWinsize{} -> loop
         SessionRequestResponse{} -> loop
