{-# OPTIONS_GHC -w #-} -- TODO(conathan): clean up and enable warnings.
{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import           Network.SSH.Client
import           Network.SSH.Connection
import           Network.SSH.Messages
import           Network.SSH.Rekey
import           Network.SSH.State

import qualified Graphics.Vty as Vty
import           Network
                   ( PortID(..), HostName, PortNumber, Socket
                   , connectTo, withSocketsDo )

import           Control.Concurrent.Async
import           Control.Exception
import           Control.Monad ( forever, void, when, (<=<) )
import qualified Data.ByteString as S
import qualified Data.ByteString.Short as Short
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L
import           System.Environment
import           System.Directory (getHomeDirectory)
import           System.IO
import           System.Posix.IO ( fdToHandle, closeFd )

#if MIN_VERSION_base(4,8,0)
import           System.Exit ( die )
#else
import           System.Exit ( exitFailure )
die :: String -> IO a
die err = hPutStrLn stderr err >> exitFailure
#endif

{-
import Openpty
import UnixTerminalFlags
import LoadKeys
-}

-- TODO(conathan): add a default algorithm selection which is better
-- than the current "all algorithms" default. Some ideas for what
-- should be in the default here:
-- https://stribika.github.io/2015/01/04/secure-secure-shell.html.

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
main = do
  args <- getArgs
  when ("-h" `elem` args || "--help" `elem` args ||
        not (length args `elem` [3,4])) $
    die . unlines $
      [ "usage: client USER SERVER_ADDR SERVER_PORT [PRIVATE_KEY]"
      , ""
      , "The optional private key file must be in OpenSSH format;"
      , "see `:/client/README.md` for details."
      ]
  let (user:host:portStr:rest) = args
  let port    = read portStr
  handle     <- withSocketsDo $
                  connectTo host (PortNumber $ fromIntegral port)
  let keyFile = case rest of
                  [file] -> Just file
                  _      -> Nothing
  let version = "SSH-HANS-Client"
  let getPw   = Just $ defaultGetPassword user host
  let prefs   = Just proposalPrefs
  let transportHook = Nothing
  let channelHook   = Just $ \client state -> do
        let e k = echoChannelHook k client state
        void $ mapConcurrently e [10..20]

  clientSt   <- defaultClientState
                  version user host port handle getPw
                  keyFile prefs transportHook channelHook
  sshClient clientSt
  -- Might be useful for sending keys to server later.
  {-
     home    <- getHomeDirectory
     pubKeys <- loadPublicKeys (home </> ".ssh" </> "authorized_keys")
     user    <- getEnv "USER"
     let creds = [(S8.pack user,pubKeys)]
  -}

echoChannelHook :: Integer -> Client -> SshState -> IO ()
echoChannelHook stop client state = do
  debug "creating a session channel ..."
  (readEvent, write, id_us) <- runConnection client state $ do
    id_us  <- sendChannelOpenSession
    (r, w) <- sendChannelRequestSubsystem id_us "echo"
    return (r, w, id_us)
  debug "created session channel!"

  debug "starting echo loop ..."
  let echoLoop :: Integer -> IO ()
      echoLoop n
        | stop == n = write Nothing
        | otherwise = do
        let msg = S8.pack (show n)
        debug $ "sending: " ++ show id_us ++ ": " ++ S8.unpack msg
        write (Just msg)
        SessionData bs <- readEvent
        debug $ "reading: " ++ show id_us ++ ": " ++ S8.unpack bs
        echoLoop (n+1)
  -- We don't actually need to run the echo loop asynchronously in
  -- this example, but we would e.g. to run a session channel and an
  -- SSH channel at the same time.
  echoThread <- async $ echoLoop 0
  void $ wait echoThread
  debug "echo loop finished!" -- We might be waiting a while ...

proposalPrefs :: SshProposalPrefs
proposalPrefs = allAlgsSshProposalPrefs
  -- If you put an unsupported algorithm in any of these lists, then
  -- you'll get an error listing all the supported algorithms for that
  -- field.

  -- The @hmac-sha2-512@ MAC causes problems with some *but not all*
  -- OpenSSH servers!?
  --
  -- Works with:
  --
  -- - linux.cecs.pdx.edu: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3
  -- - localhost:          SSH-2.0-OpenSSH_6.7p1 Ubuntu-5ubuntu1.3
  -- - cs.uoregon.edu:     SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.2
  --
  -- Does not work with:
  --
  -- - src.galois.com:     SSH-2.0-OpenSSH_5.3
  -- - alumni.cs.wisc.edu: SSH-2.0-OpenSSH_5.3
  --
  -- According to OpenSSH docs, support for @hmac-sha2-512@ was not
  -- added until version 5.9: http://www.openssh.com/txt/release-5.9.
  { sshEncAlgsPrefs  = SshAlgs ["aes256-ctr"] ["aes192-ctr"]
  , sshMacAlgsPrefs  = SshAlgs ["hmac-sha2-256"] ["hmac-sha2-512"]
  , sshCompAlgsPrefs = SshAlgs ["none"] ["none"]
  }
