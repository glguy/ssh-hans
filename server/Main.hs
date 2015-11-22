{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import           Network.SSH.Packet ( SshIdent(..) )
import           Network.SSH.Server
import           Network.SSH.Messages
import           Network.SSH.UserAuth

import           Control.Monad ( forever )
import           Control.Exception
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L
import           Data.Monoid ( mempty )
import           Network
                     ( PortID(..), HostName, PortNumber, withSocketsDo, listenOn
                     , accept, Socket )
import           System.Directory ( doesFileExist )
import           System.IO ( Handle, hClose )

import System.Posix.IO ( fdToHandle, closeFd )
import Foreign.Marshal ( allocaBytes )
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
main  = withSocketsDo $
  do sock             <- listenOn (PortNumber 2200)
     (privKey,pubKey) <- loadKeys

     home       <- getHomeDirectory
     mbUserPubKey <- loadPublicKey (home </> ".ssh" </> "id_ecdsa.pub")
     userPubKey <- case mbUserPubKey of
                     Left e -> fail ("bad public key: " ++ e)
                     Right x -> return x
     user <- getEnv "USER"
     let creds = [(S8.pack user,userPubKey)]

     sshServer greeting privKey pubKey (mkServer creds sock)

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

type Credentials = [(S.ByteString, SshPubCert)]

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
         allocaBytes 1024 $ \p ->
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

       let config = mempty { Vty.inputFd  = Just slaveFd
                           , Vty.outputFd = Just slaveFd
                           , Vty.termName = Just (S8.unpack term)
                           }

       SetGame.gameMain config
       hClose masterH

  cAuthHandler session_id username svc m@(SshAuthPublicKey alg key mbSig) =
    case lookup username creds of
      Just pub | pub == key ->
       case mbSig of
         Nothing -> return (AuthPkOk alg key)
         Just sig
           | verifyPubKeyAuthentication session_id username svc alg key sig
                       -> return AuthAccepted
           | otherwise -> return (AuthFailed ["publickey"])
      _ -> return (AuthFailed ["publickey"])

  cAuthHandler session_id user svc m =
    do print (user,m)
       return (AuthFailed ["publickey"])

loadKeys :: IO (PrivateKey, PublicKey)
loadKeys  =
  do privExists <- doesFileExist "server.priv"
     pubExists  <- doesFileExist "server.pub"

     if privExists && pubExists
        then do priv <- readFile "server.priv"
                pub  <- readFile "server.pub"
                return (read priv, read pub) -- icky

        else do pair@(priv, pub) <- genKeyPair
                writeFile "server.priv" (show priv)
                writeFile "server.pub"  (show pub)
                return pair
