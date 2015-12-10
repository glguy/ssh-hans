{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import           Network.SSH.Messages
import           Network.SSH.Packet ( SshIdent(..) )
import           Network.SSH.Client
import           Network.SSH.Named
import           Network.SSH.PubKey
import           Network.SSH.PrivateKeyFormat

import           Control.Monad ( forever, when, (<=<) )
import           Control.Exception
import qualified Data.ByteString as S
import qualified Data.ByteString.Short as Short
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L
import           Network
                     ( PortID(..), HostName, PortNumber, connectTo, withSocketsDo
                     , Socket )
import           System.IO ( Handle, hClose )

import System.IO
import System.Posix.IO ( fdToHandle, closeFd )
import Control.Concurrent
import System.FilePath
import System.Environment
import System.Exit ( die )
import System.Directory (getHomeDirectory)
import qualified Graphics.Vty as Vty

{-
import Openpty
import UnixTerminalFlags
import LoadKeys
-}

-- TODO(conathan): change default cipher suite in client, or at least
-- make the cipher suite configurable.

-- TODO(conathan): make client GHC 7.8 compatible.

-- TODO(conathan): implement key reexchange after threshold: RFC 4253
-- section 9 suggests that key reexchange should happen about every
-- hour or every GB of traffic, whichever comes first.

-- TODO(conathan): sanitize terminal output: RFC 4253 repeatedly
-- suggests that any output from an untrusted server be sanitized
-- before displaying to the screen, to avoid
-- terminal-control-char-based attacks. We may want to implement this
-- at some point, or at least warn users about this in the docs.

-- TODO(conathan): add real argument parsing? E.g., OpenSSh uses your
-- current username unless you put '<user>@' in from of the host name.
main :: IO ()
main = withSocketsDo $ do
  args <- getArgs
  when ("-h" `elem` args || "--help" `elem` args ||
        not (length args `elem` [3,4])) $
    die . unlines $
      [ "usage: client USER SERVER_ADDR SERVER_PORT [PRIVATE_KEY]"
      , ""
      , "The optional private key file must be in OpenSSH format;"
      , "see `:/server/README.md` for details."
      ]
  let (user:host:portStr:rest) = args
  let port                     = fromInteger $ read portStr
  keys <- case rest of
    [file] -> loadPrivateKeys file
    _      -> return []

  let prompt = user ++ "@" ++ host ++ "'s password: "
  let getPw  = S8.pack <$> getPassword prompt

  handle <- connectTo host (PortNumber port)
-- Might be useful for sending keys to server later.
{-
     home    <- getHomeDirectory
     pubKeys <- loadPublicKeys (home </> ".ssh" </> "authorized_keys")
     user    <- getEnv "USER"
     let creds = [(S8.pack user,pubKeys)]
-}
     -- sshServer (mkServer sAuth creds sock)
  sshClient (mkClientState handle user getPw keys)


mkClientState ::
  Handle -> String -> IO S.ByteString -> [Named (SshPubCert,PrivateKey)] ->
  ClientState
mkClientState handle user getPw keys = ClientState{..}
  where
  csIdent = greeting
  csNet   = mkClient handle
  csUser  = S8.pack user
  csGetPw = getPw
  csKeys  = keys

greeting :: SshIdent
greeting  = SshIdent "SSH-2.0-SSH_HaLVM_2.0_Client"

mkClient :: Handle -> Client
mkClient h = Client { .. }
  where
  cGet   = S.hGetSome h
  cPut   = S.hPutStr  h . L.toStrict
  cClose =   hClose   h
  cLog   = putStrLn

-- Based on http://stackoverflow.com/a/4064482/470844
getPassword :: String -> IO String
getPassword prompt = do
  putStr prompt
  hFlush stdout
  pass <- withEcho False getLine
  putChar '\n'
  return pass
  where
  withEcho :: Bool -> IO a -> IO a
  withEcho echo action = do
    old <- hGetEcho stdin
    bracket_ (hSetEcho stdin echo) (hSetEcho stdin old) action

  -- Need to refactor 'Client' to remove fields not shared between
  -- client and server. See Network.ssh.state.

{-
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
-}


{-
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
-}