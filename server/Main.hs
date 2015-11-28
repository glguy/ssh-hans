{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import           Network.SSH.Messages
import           Network.SSH.Packet ( SshIdent(..) )
import           Network.SSH.Server
import           Network.SSH.Named
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
import           System.IO.Error (isDoesNotExistError)

import System.Posix.IO ( fdToHandle, closeFd )
import Control.Concurrent
import System.FilePath
import System.Environment
import System.Directory (getHomeDirectory)
import qualified SetGame
import qualified Graphics.Vty as Vty

import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.Hash.Algorithms as Hash
import Data.ByteArray (convert)
import Crypto.Error (throwCryptoErrorIO)
import Crypto.Random(getRandomBytes)

import Openpty
import UnixTerminalFlags
import LoadKeys

main :: IO ()
main = withSocketsDo $
  do sock             <- listenOn (PortNumber 2200)

     myRsaAuth <- loadRsaAuth
     myEdAuth  <- loadEdAuth
     let sAuth = [myRsaAuth, myEdAuth]

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

rsaAuth :: RSA.PrivateKey -> SshSessionId -> IO SshSig
rsaAuth privKey (SshSessionId token) =
  do Right sig <- RSA.signSafer (Just Hash.SHA1) privKey token
     return (SshSigRsa sig)

edAuth :: Ed25519.SecretKey -> Ed25519.PublicKey -> SshSessionId -> IO SshSig
edAuth priv pub (SshSessionId token) =
  return (SshSigEd25519 (convert (Ed25519.sign priv pub token)))

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

  cOpenShell term winsize termflags eventChannel writeBytes =
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

loadRsaAuth :: IO ServerCredential
loadRsaAuth =
  do privExists <- doesFileExist "server.priv"
     pubExists  <- doesFileExist "server.pub"

     (pub,priv) <-
       if privExists && pubExists
         then do pub  <- readFile "server.pub"
                 priv <- readFile "server.priv"
                 return (read pub, read priv) -- icky

         else do (pub, priv) <- RSA.generate 256{-bytes-} 0x10001{-e-}
                 writeFile "server.pub"  (show pub)
                 writeFile "server.priv" (show priv)
                 return (pub,priv)


     let cert = SshPubRsa (RSA.public_e pub) (RSA.public_n pub)
     return (Named "ssh-rsa" (cert, rsaAuth priv))

loadEdAuth :: IO ServerCredential
loadEdAuth =
  do res <- try (S.readFile "server.ed")
     bytes <- case res of
                Right bytes -> return bytes
                Left e
                  | isDoesNotExistError e ->
                     do xs <- getRandomBytes 32
                        S.writeFile "server.ed" xs
                        return xs
                  | otherwise -> throwIO e

     priv <- throwCryptoErrorIO (Ed25519.secretKey bytes)
     let pub = Ed25519.toPublic priv
     return (Named "ssh-ed25519" (SshPubEd25519 (convert pub), edAuth priv pub))
