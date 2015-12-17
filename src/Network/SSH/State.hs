{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE BangPatterns #-}

module Network.SSH.State where


import           Network.SSH.Ciphers
import           Network.SSH.Mac
import           Network.SSH.Messages
import           Network.SSH.Named
import           Network.SSH.Packet
import           Network.SSH.PubKey (PrivateKey)
import           Network.SSH.TerminalModes

import           Data.Char (isControl)
import           Data.IORef
import           Data.Word
import           Data.Serialize
import           Control.Concurrent
import           Control.Monad
import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L
import           Crypto.Random

debug :: String -> IO ()
debug s = putStrLn $ "debug: " ++ s

-- Server Internals ------------------------------------------------------------

data AuthResult
  = AuthFailed [ShortByteString]
  | AuthAccepted
  | AuthPkOk S.ByteString SshPubCert

data SessionEvent
  = SessionData S.ByteString
  | SessionClose
  | SessionEof
  | SessionWinsize SshWindowSize

-- TODO(conathan): rename, e.g 'ClientState', since we are adding
-- client support. Or maybe, refactor this into client specific state
-- (if any; the 'cOpenShell' may be client only) and general "other
-- end of the connection state". From this symmetric point of view, it
-- might make sense to call the other end the client, but that could
-- be confusing since we also define client and server modules. Better
-- to call it something else ...
data Client = Client
  -- | Read up to 'n' bytes from network socket
  { cGet         :: Int -> IO S.ByteString

  -- | Put bytes on network socket
  , cPut         :: L.ByteString -> IO ()

  -- | Close network socket
  , cClose       :: IO ()

  -- | Log messages for events related to this client
  , cLog         :: String -> IO ()

  -- | TERM, initial window dimensions, termios flags, incoming events, write callback
  , cOpenShell   :: S.ByteString -> SshWindowSize -> [(TerminalFlag, Word32)] ->
                    Chan SessionEvent ->
                    (Maybe S.ByteString -> IO ()) ->
                    IO ()

  , cDirectTcp   :: S.ByteString -> Word32 ->
                    Chan SessionEvent ->
                    (Maybe S.ByteString -> IO ()) ->
                    IO Bool

  -- | Client requested executing a command. Return True to accept
  , cRequestExec :: S.ByteString ->
                    Chan SessionEvent ->
                    (Maybe S.ByteString -> IO ()) ->
                    IO Bool

  -- | ByteString argument is user name
  , cAuthHandler :: SshSessionId  ->
                    S.ByteString  ->
                    SshService    ->
                    SshAuthMethod ->
                    IO AuthResult
  }


data Role = ClientRole | ServerRole
  deriving (Eq,Show)

-- | Select our value from client and server values according to 'Role'.
--
-- Mnemonic: argument order is the same as the function name: client
-- and then server.
clientAndServer2usAndThem ::
  Role -> a {- ^ client value -} -> a {- ^ server value -} -> (a, a)
clientAndServer2usAndThem ClientRole c s = (c, s)
clientAndServer2usAndThem ServerRole c s = (s, c)

clientAndServer2us :: Role -> a -> a -> a
clientAndServer2us role c s = fst $ clientAndServer2usAndThem role c s

clientAndServer2them :: Role -> a -> a -> a
clientAndServer2them role c s = snd $ clientAndServer2usAndThem role c s


usAndThem2clientAndServer ::
  Role -> a {- ^ our value -} -> a {- ^ their value -} -> (a, a)
usAndThem2clientAndServer ClientRole us them = (us, them)
usAndThem2clientAndServer ServerRole us them = (them, us)

usAndThem2c :: Role -> a -> a -> a
usAndThem2c role us them = fst $ usAndThem2clientAndServer role us them

usAndThem2s :: Role -> a -> a -> a
usAndThem2s role us them = snd $ usAndThem2clientAndServer role us them


type CompressFun = S.ByteString -> IO L.ByteString
type DecompressFun = CompressFun

data SshState = SshState
  { sshRecvState :: !(IORef (Word32, Cipher, ActiveCipher, Mac, DecompressFun)) -- ^ Client context
  , sshBuf       :: !(IORef S.ByteString)
  , sshSendState :: !(MVar (Word32, Cipher, ActiveCipher, Mac, CompressFun, ChaChaDRG)) -- ^ Server encryption context
  , sshSessionId :: !(IORef (Maybe SshSessionId))
  , sshRole          :: Role
  , sshAuthMethods   :: [ServerCredential]
  , sshIdents        :: !(IORef (SshIdent, SshIdent)) -- server, client
  , sshProposalPrefs :: SshProposalPrefs
  }

-- | Partial specification of an 'SshProposal'.
data SshProposalPrefs = SshProposalPrefs
  { sshKexAlgsPrefs           :: NameList
  , sshServerHostKeyAlgsPrefs :: NameList
  , sshEncAlgsPrefs           :: !SshAlgs
  , sshMacAlgsPrefs           :: !SshAlgs
  , sshCompAlgsPrefs          :: !SshAlgs
  } deriving (Eq,Show,Read)

type ServerCredential = Named (SshPubCert, PrivateKey)

-- TODO(conathan): factor out server credentials since they don't make
-- sense in the client.
initialState ::
  SshProposalPrefs -> Role -> [ServerCredential] -> IO SshState
initialState prefs sshRole creds =
  do drg          <- drgNew
     let none = namedThing cipher_none
     sshRecvState <- newIORef (0,none
                                ,activateCipherD_none
                                ,namedThing mac_none ""
                                ,return . L.fromStrict) -- no decompression
     sshSendState <- newMVar  (0,none
                                ,activateCipherE_none
                                ,namedThing mac_none ""
                                ,return . L.fromStrict -- no compression
                                ,drg)
     sshBuf       <- newIORef S.empty
     sshSessionId <- newIORef Nothing
     sshIdents    <- newIORef (error "idents uninitialized")
     let sshAuthMethods   = creds
     let sshProposalPrefs = prefs
     return SshState { .. }

-- | Construct a new, random cookie
newCookie :: IO SshCookie
newCookie = SshCookie `fmap` getRandomBytes 16

send :: Client -> SshState -> SshMsg -> IO ()
send client SshState { .. } msg =
  modifyMVar_ sshSendState $ \(seqNum, cipher, activeCipher, mac, comp, gen) ->
    do payload <- comp (runPut (putSshMsg msg))
       let (pkt,activeCipher',gen') = putSshPacket seqNum cipher activeCipher mac gen payload
       -- TODO(conathan): how to tell if the connection is closed
       -- here? Would like to raise an error when trying to write to a
       -- closed connection, no?
       cPut client pkt
       return (seqNum+1, cipher, activeCipher',mac, comp, gen')

-- | Like 'receive', but fail when receiving an unexpected msg.
receiveSpecific :: SshMsgTag -> Client -> SshState -> IO SshMsg
receiveSpecific tag client sshState = do
  msg <- receive client sshState
  if sshMsgTag msg == tag
  then return msg
  else fail $ "unexpected msg of type" ++ show (sshMsgTag msg)

receive :: Client -> SshState -> IO SshMsg
receive client SshState { .. } = loop
  where
  loop =
    do (seqNum, cipher, activeCipher, mac, decomp) <- readIORef sshRecvState
       (payload, activeCipher') <- parseFrom client sshBuf
                                 $ getSshPacket seqNum cipher activeCipher mac
       payload' <- decomp payload
       msg <- either fail return $ runGetLazy getSshMsg payload'
       let !seqNum1 = seqNum + 1
       writeIORef sshRecvState (seqNum1, cipher, activeCipher', mac, decomp)
       case msg of
         SshMsgIgnore _                      -> loop
         SshMsgDebug display m _ | display   -> do cLog client (filter (not . isControl)
                                                                       (S8.unpack m))
                                                   loop -- XXX drop controls
                                 | otherwise -> loop
         SshMsgDisconnect reason msg' _lang   ->
           fail $ "other end disconnected: " ++ show reason ++ ": " ++
                  S8.unpack msg'
         _                                   -> return msg

parseFrom :: Client -> IORef S.ByteString -> Get a -> IO a
parseFrom handle buffer body =
  do bytes <- readIORef buffer
     go (S.null bytes) (runGetPartial body bytes)

  where
  -- boolean: beginning of packet
  go beginning (Partial k) =
       -- If the connection gets closed the handle will still be open
       -- -- i.e. 'hIsClosed' will return false -- but reads on the
       -- handle will return the empty string.
    do bytes <- cGet handle 32752
       when (beginning && S.null bytes) (fail "Connection closed")
       go False (k bytes)

  go _ (Done a bs) =
    do writeIORef buffer bs
       return a

  go _ (Fail s _) = fail s
