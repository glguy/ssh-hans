{-# LANGUAGE RecordWildCards #-}
module Network.SSH.State where


import Network.SSH.Ciphers
import Network.SSH.Messages
import Network.SSH.Packet
import Network.SSH.TerminalModes
import Network.SSH.Mac

import Data.IORef
import Data.Word
import Data.Serialize.Get
import Control.Concurrent
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L


-- Server Internals ------------------------------------------------------------

data AuthResult = AuthFailed [S.ByteString]
                | AuthAccepted
                | AuthPkOk S.ByteString SshPubCert


data SessionEvent
  = SessionData S.ByteString
  | SessionClose
  | SessionWinsize SshWindowSize

data Client = Client { cGet         :: Int -> IO S.ByteString
                     , cPut         :: L.ByteString -> IO ()
                     , cOpenShell   :: (S.ByteString, SshWindowSize, [(TerminalFlag, Word32)]) ->
                                        Chan SessionEvent ->
                                        (Maybe S.ByteString -> IO ()) ->
                                        IO ()
                     , cClose       :: IO ()
                     , cAuthHandler :: SshSessionId  ->
                                       S.ByteString  ->
                                       SshService    ->
                                       SshAuthMethod ->
                                       IO AuthResult
                     }


data SshState = SshState { sshDecC  :: !(IORef Cipher) -- ^ Client decryption context
                         , sshAuthC :: !(IORef Mac)    -- ^ Client authentication context
                         , sshBuf   :: !(IORef S.ByteString)
                         , sshSendState :: !(MVar (Cipher, Mac)) -- ^ Server encryption context
                         }

initialState :: IO SshState
initialState  =
  do sshDecC  <- newIORef cipher_none_dec
     sshAuthC <- newIORef mac_none
     sshBuf   <- newIORef S.empty
     sshSendState <- newMVar (cipher_none_enc, mac_none)
     return SshState { .. }

send :: Client -> SshState -> SshMsg -> IO ()
send client SshState { .. } msg =
  modifyMVar_ sshSendState $ \(cipher, mac) ->
    do let (pkt,cipher',mac') = putSshPacket cipher mac (putSshMsg msg)
       cPut client pkt
       return (cipher', mac')


receive :: Client -> SshState -> IO SshMsg
receive client SshState { .. } = loop
  where
  loop =
    do cipher <- readIORef sshDecC
       mac    <- readIORef sshAuthC
       res    <- parseFrom client sshBuf (getSshPacket cipher mac getSshMsg)
       case res of

         Right (msg, cipher', mac') ->
           do writeIORef sshDecC  cipher'
              writeIORef sshAuthC mac'
              case msg of
                SshMsgIgnore _                      -> loop
                SshMsgDebug display m _ | display   -> S8.putStrLn m >> loop
                                        | otherwise -> loop
                _                                   -> return msg

         Left err ->
           do putStrLn err
              fail "Failed when reading from client"

parseFrom :: Client -> IORef S.ByteString -> Get a -> IO (Either String a)
parseFrom handle buffer body =
  do bytes <- readIORef buffer

     if S.null bytes
        then go True (Partial (runGetPartial body))
        else go True (runGetPartial body bytes)

  where

  go True  (Partial k) = do bytes <- cGet handle 1024
                            if S.null bytes
                               then fail "Client closed connection"
                               else go (S.length bytes == 1024) (k bytes)

  go False (Partial k) = go False (k S.empty)
  go _     (Done a bs) = do writeIORef buffer bs
                            return (Right a)
  go _     (Fail s _)  = return (Left s)


