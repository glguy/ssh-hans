{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import           Network.SSH.Transport

import           Control.Concurrent ( forkIO )
import qualified Control.Exception as X
import           Control.Monad ( forever )
import           Crypto.Classes.Exceptions ( newGenIO, genBytes )
import           Crypto.Random.DRBG ( CtrDRBG )
import qualified Data.ByteString.Char8 as S
import           Data.Serialize ( Get, runPut, runGet, runGetPartial, Result(..) )
import           System.IO ( Handle, hClose )
import           Network ( PortID(..), withSocketsDo, listenOn, accept )


main = withSocketsDo $
  do sock <- listenOn (PortNumber 2200)
     forever $ do (client,host,port) <- accept sock
                  putStrLn ("Got a client from: " ++ host ++ ":" ++ show port)
                  _ <- forkIO (sayHello client `X.finally` hClose client)
                  return ()



parseFrom :: Handle -> Get a -> IO (Either String a)
parseFrom handle body = go True (Partial (runGetPartial body))
  where
  go True  (Partial k) = do bytes <- S.hGetSome handle 1024
                            go (S.length bytes == 1024) (k bytes)

  go False (Partial k) = go False (k S.empty)
  go _     (Done a _)  = return (Right a)
  go _     (Fail s _)  = return (Left s)


greeting :: SshIdent
greeting  = SshIdent { sshProtoVersion    = "2.0"
                     , sshSoftwareVersion = "SSH_HaNS_1.0"
                     , sshComments        = ""
                     }

sayHello :: Handle -> IO ()
sayHello client =
  do S.hPutStr client (runPut (putSshIdent greeting))
     msg <- parseFrom client getSshIdent
     print msg
     case msg of
       Right ident -> do print ident
                         startKex client ident
       Left err    -> return ()


supportedKex :: SshCookie -> SshKeyExchange
supportedKex sshCookie =
  SshKeyExchange { sshKexAlgs           = [ "diffie-hellman-group1-sha1" ]
                 , sshServerHostKeyAlgs = [ "ssh-dss" ]
                 , sshEncAlgs           = SshAlgs [ "3des-cbc" ] [ "3des-cbc" ]
                 , sshMacAlgs           = SshAlgs [ "hmac-sha1" ] [ ]
                 , sshCompAlgs          = SshAlgs [] []
                 , sshLanguages         = SshAlgs [] []
                 , sshFirstKexFollows   = False
                 , ..
                 }

newCookie :: CtrDRBG -> (SshCookie,CtrDRBG)
newCookie g = (SshCookie bytes, g')
  where
  (bytes,g') = genBytes 16 g

startKex :: Handle -> SshIdent -> IO ()
startKex client ident =
  do gen <- newGenIO
     let (cookie,gen') = newCookie gen
     S.hPutStr client (runPut (putSshPacket Nothing putSshKeyExchange (supportedKex cookie)))

     msg <- parseFrom client (getSshPacket Nothing getSshKeyExchange)
     case msg of
       Right pkt -> print pkt
       Left err  -> print err
