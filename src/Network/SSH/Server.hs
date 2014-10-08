{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.Server (

    Server(..)
  , Client(..)
  , AuthResult(..)
  , sshServer

  , PrivateKey()
  , PublicKey()
  , genKeyPair

  ) where

import           Network.SSH.Ciphers
import           Network.SSH.Keys
import           Network.SSH.Mac
import           Network.SSH.Messages
import           Network.SSH.Packet

import           Control.Concurrent ( forkIO )
import qualified Control.Exception as X
import           Control.Applicative ( Applicative )
import           Control.Monad ( forever, when )
import           Control.Monad.CryptoRandom ( crandomR )
import           Crypto.Classes.Exceptions ( newGenIO, genBytes, splitGen )
import           Crypto.Random.DRBG ( CtrDRBG )
import           Crypto.Types.PubKey.RSA ( PublicKey(..), PrivateKey(..) )
import           Codec.Crypto.RSA.Exceptions
                     ( modular_exponentiation, rsassa_pkcs1_v1_5_sign, hashSHA1
                     , HashInfo(..), generateKeyPair, generatePQ )
import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.IORef
                     ( IORef, newIORef, readIORef, writeIORef, modifyIORef )
import           Data.Serialize
                     ( Get, runGetPartial, Result(..), runPutLazy )
import           Data.Word ( Word32 )
import           Data.Foldable ( for_ )
import           System.IO
import           Control.Concurrent.STM

-- Containers
import           Data.Map ( Map )
import qualified Data.Map as Map

-- Transformers
import           Control.Monad.IO.Class
import           Control.Monad.Trans.Class
import           Control.Monad.Trans.Reader
import           Control.Monad.Trans.State

-- Custom handles
import System.IO.Streams
import System.IO.Streams.Handle ( streamPairToHandle )


-- Public API ------------------------------------------------------------------

data Server = Server { sAccept :: IO Client
                     }

data AuthResult = AuthFailed [S.ByteString]
                | AuthAccepted
                | AuthPkOk S.ByteString SshPubCert

data Client = Client { cGet         :: Int -> IO S.ByteString
                     , cPut         :: L.ByteString -> IO ()
                     , cOpenShell   :: Handle -> IO ()
                     , cClose       :: IO ()
                     , cAuthHandler :: SshSessionId  ->
                                       S.ByteString  ->
                                       SshService    ->
                                       SshAuthMethod ->
                                       IO AuthResult
                     }

sshServer :: SshIdent -> PrivateKey -> PublicKey -> Server -> IO ()
sshServer ident privKey pubKey sock = loop =<< newGenIO
  where
  loop g = do client <- sAccept sock
              let (g',gClient) = splitGen g
              _ <- forkIO $
                     do state <- initialState
                        result <- sayHello state ident gClient privKey pubKey client
                        for_ result $ \(user,svc) ->
                          case svc of
                            SshConnection -> startConnectionService client state
                            _             -> return ()

                      `X.finally` cClose client

              loop g'

-- | Generates a 1024-bit RSA key pair.
genKeyPair :: IO (PrivateKey, PublicKey)
genKeyPair  =
  do gen <- newGenIO
     let (pub,priv,_) = generateKeyPair (gen :: CtrDRBG) 1024
         (p,q,_)      = generatePQ gen (1024 `div` 8)
         priv'        = priv { private_p = p, private_q = q }
     return (priv', pub)


-- Server Internals ------------------------------------------------------------

data SshState = SshState { sshDecC  :: !(IORef Cipher) -- ^ Client decryption context
                         , sshEncS  :: !(IORef Cipher) -- ^ Server encryption context
                         , sshAuthC :: !(IORef Mac)    -- ^ Client authentication context
                         , sshAuthS :: !(IORef Mac)    -- ^ Server authentication context
                         , sshBuf   :: !(IORef S.ByteString)
                           -- ^ Receive buffer
                         }

initialState :: IO SshState
initialState  =
  do sshDecC  <- newIORef cipher_none
     sshEncS  <- newIORef cipher_none
     sshAuthC <- newIORef mac_none
     sshAuthS <- newIORef mac_none
     sshBuf   <- newIORef S.empty
     return SshState { .. }


-- | Install new keys (and algorithms) into the SshState.
transitionKeys :: Keys -> SshState -> IO ()
transitionKeys Keys { .. } SshState { .. } =
  do writeIORef sshDecC (snd (cipher_aes128_cbc (kpClientToServer kInitialIV) (kpClientToServer kEncKey)))
     writeIORef sshEncS (fst (cipher_aes128_cbc (kpServerToClient kInitialIV) (kpServerToClient kEncKey)))

     modifyIORef sshAuthC $ \ mac ->
       let mac' = mac_hmac_sha1 (kpClientToServer kIntegKey)
        in mac `switch` mac'

     modifyIORef sshAuthS $ \ mac ->
       let mac' = mac_hmac_sha1 (kpServerToClient kIntegKey)
        in mac `switch` mac'

     putStrLn "New keys installed."




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


send :: Client -> SshState -> SshMsg -> IO ()
send client SshState { .. } msg =
  do cipher <- readIORef sshEncS
     mac    <- readIORef sshAuthS
     let (pkt,cipher',mac') = putSshPacket cipher mac (putSshMsg msg)
     cPut client pkt
     writeIORef sshEncS  cipher'
     writeIORef sshAuthS mac'


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
                SshMsgDebug display m _ | display   -> S.putStrLn m >> loop
                                        | otherwise -> loop
                _                                   -> return msg

         Left err ->
           do putStrLn err
              fail "Failed when reading from client"

sayHello ::
  SshState ->
  SshIdent ->
  CtrDRBG ->
  PrivateKey ->
  PublicKey ->
  Client ->
  IO (Maybe (S.ByteString, SshService))
sayHello state ident gen priv pub client =
  do cPut client (runPutLazy (putSshIdent ident))
     msg   <- parseFrom client (sshBuf state) getSshIdent
     print msg
     case msg of
       Right v_c -> do print v_c
                       startKex gen priv pub (sshDhHash v_c ident) state client
       Left err  -> do print err
                       return Nothing


supportedKex :: SshCookie -> SshKex
supportedKex sshCookie =
  SshKex { sshKexAlgs           = [ "diffie-hellman-group1-sha1" ]
         , sshServerHostKeyAlgs = [ "ssh-rsa" ]
         , sshEncAlgs           = SshAlgs [ "aes128-cbc" ] [ "aes128-cbc" ]
         , sshMacAlgs           = SshAlgs [ "hmac-sha1" ] [ "hmac-sha1" ]
         , sshCompAlgs          = SshAlgs [ "none" ] [ "none" ]
         , sshLanguages         = SshAlgs [] []
         , sshFirstKexFollows   = False
         , ..
         }

newCookie :: CtrDRBG -> (SshCookie,CtrDRBG)
newCookie g = (SshCookie bytes, g')
  where
  (bytes,g') = genBytes 16 g

startKex :: CtrDRBG -> PrivateKey -> PublicKey
         -> (SshKex -> SshKex -> SshPubCert -> Integer -> Integer -> Integer -> S.ByteString)
         -> SshState -> Client -> IO (Maybe (S.ByteString, SshService))
startKex gen priv pub mkHash state client =
  do let (cookie,gen')  = newCookie gen
         i_s            = supportedKex cookie

     send client state (SshMsgKexInit i_s)

     i_c <- waitForClientKex
     putStrLn "Got KexInit"
     startDh client gen' priv pub state (mkHash i_c i_s)
  where
  waitForClientKex =
    do msg <- receive client state
       case msg of
         SshMsgKexInit i_c -> return i_c
         _                 -> waitForClientKex


data DiffieHellmanGroup = DiffieHellmanGroup {
       dhgP    :: Integer -- ^The prime.
     , dhgG    :: Integer -- ^The generator.
     , dhgSize :: Int     -- ^Size in bits.
     }
 deriving (Eq, Show)

-- |Group 2 from RFC 2409
oakley2 :: DiffieHellmanGroup
oakley2 = DiffieHellmanGroup {
    dhgP = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
  , dhgG = 2
  , dhgSize = 1024
  }

startDh :: Client -> CtrDRBG -> PrivateKey -> PublicKey -> SshState
        -> (SshPubCert -> Integer -> Integer -> Integer -> S.ByteString)
        -> IO (Maybe (S.ByteString, SshService))
startDh client gen priv@PrivateKey{..} pub@PublicKey{..} state mkHash =
  do SshMsgKexDhInit e <- receive client state
     let Right (y,gen') = crandomR (1,private_q) gen
         f              = modular_exponentiation (dhgG oakley2) y (dhgP oakley2)
         k              = modular_exponentiation e y (dhgP oakley2)
         cert           = SshPubRsa public_e public_n
         hash           = mkHash cert e f k
         h              = hashFunction hashSHA1 (L.fromStrict hash)
         h'             = L.toStrict h

         sig            = rsassa_pkcs1_v1_5_sign hashSHA1 priv h

         session_id     = SshSessionId h'
         keys           = genKeys (hashFunction hashSHA1) k h' session_id


     putStrLn "Sending DH reply"
     send client state (SshMsgKexDhReply cert f (SshSigRsa (L.toStrict sig)))

     putStrLn "Waiting for response"
     getDhResponse client gen' priv pub session_id state keys


getDhResponse :: Client -> CtrDRBG -> PrivateKey -> PublicKey -> SshSessionId
              -> SshState -> Keys -> IO (Maybe (S.ByteString, SshService))
getDhResponse client _gen _priv _pub session_id state keys =
  do SshMsgNewKeys <- receive client state
     send client state SshMsgNewKeys

     transitionKeys keys state

     let notAvailable = send client state
                      $ SshMsgDisconnect SshDiscServiceNotAvailable "" "en-us"

     req <- receive client state
     case req of

       SshMsgServiceRequest SshUserAuth ->
         do send client state (SshMsgServiceAccept SshUserAuth)
            authLoop

        where
         authLoop =
           do userReq <- receive client state
              case userReq of

                SshMsgUserAuthRequest user svc method ->
                  do result <- cAuthHandler client session_id user svc method

                     case result of

                       AuthAccepted ->
                         do send client state SshMsgUserAuthSuccess
                            return (Just (user, svc))

                       AuthPkOk keyAlg key ->
                         do send client state
                              (SshMsgUserAuthPkOk keyAlg key)
                            authLoop

                       AuthFailed [] ->
                         do send client state (SshMsgUserAuthFailure [] False)
                            return Nothing

                       AuthFailed ms ->
                         do send client state (SshMsgUserAuthFailure ms False)
                            authLoop


                _ -> notAvailable >> return Nothing

       _ -> notAvailable >> return Nothing


data SshChannel = SshChannel
  { sshChannelRemote        :: !Word32
  , sshChannelEnv           :: [(S.ByteString,S.ByteString)]
  , sshChannelWindowSize    :: Word32
  , sshChannelMaximumPacket :: Word32
  , sshChannelPty           :: Maybe (S.ByteString, Word32, Word32) -- Term, width, height
  , sshChannelData          :: TVar L.ByteString
  }

----------------------
-- Connection operations
----------------------

newtype Connection a = Connection
  { runConnection :: ReaderT (Client, SshState) (StateT (Map Word32 SshChannel) IO) a }
  deriving (Functor, Applicative, Monad, MonadIO)

connectionReceive :: Connection SshMsg
connectionReceive = Connection $
  do (client, state) <- ask
     liftIO (receive client state)

connectionSend :: SshMsg -> Connection ()
connectionSend msg = Connection $
  do (client, state) <- ask
     liftIO (send client state msg)

connectionGetChannels :: Connection (Map Word32 SshChannel)
connectionGetChannels = Connection (lift get)

connectionSetChannels :: Map Word32 SshChannel -> Connection ()
connectionSetChannels = Connection . lift . put

connectionModifyChannels :: (Map Word32 SshChannel -> Map Word32 SshChannel) -> Connection ()
connectionModifyChannels = Connection . lift . modify

----------------------

startConnectionService :: Client -> SshState -> IO ()
startConnectionService client state
  = flip evalStateT Map.empty
  . flip runReaderT (client, state)
  . runConnection
  $ connectionService

connectionService :: Connection ()
connectionService =
  do msg <- connectionReceive
     liftIO (print msg)
     case msg of
       SshMsgChannelOpen SshChannelTypeSession
         senderChannel initialWindowSize maximumPacketSize ->
           do startSession senderChannel initialWindowSize maximumPacketSize
              connectionService

       SshMsgChannelOpen _ senderChannel _ _ ->
           do connectionSend $
                SshMsgChannelOpenFailure senderChannel SshOpenAdministrativelyProhibited "" ""
              connectionService

       SshMsgChannelRequest req chan wantReply ->
         do channelRequest req chan wantReply
            connectionService

       SshMsgChannelData chan bytes ->
         do channelData chan bytes
            connectionService

       _ -> return ()


startSession :: Word32 -> Word32 -> Word32 -> Connection ()
startSession senderChannel initialWindowSize maximumPacketSize =
  do channels <- connectionGetChannels

     dataVar  <- liftIO (atomically (newTVar L.empty))

     let nextChannelId =
           case Map.maxViewWithKey channels of
             Nothing        -> 0
             Just ((k,_),_) -> k+1

         channel = SshChannel
                     { sshChannelRemote        = senderChannel
                     , sshChannelWindowSize    = initialWindowSize
                     , sshChannelMaximumPacket = maximumPacketSize
                     , sshChannelEnv           = []
                     , sshChannelPty           = Nothing
                     , sshChannelData          = dataVar
                     }

     connectionSetChannels (Map.insert nextChannelId channel channels)

     connectionSend $
       SshMsgChannelOpenConfirmation
         senderChannel
         nextChannelId
         initialWindowSize
         maximumPacketSize

channelData :: Word32 -> S.ByteString -> Connection ()
channelData channelId bytes =
  do channels <- connectionGetChannels
     case Map.lookup channelId channels of
       Nothing -> fail "Bad channel!"
       Just channel -> liftIO
                     $ atomically
                     $ modifyTVar (sshChannelData channel) (`L.append` L.fromStrict bytes)

channelRequest :: SshChannelRequest -> Word32 -> Bool -> Connection ()
channelRequest request channelId wantReply =
  do channels <- connectionGetChannels

     case Map.lookup channelId channels of
       Nothing      -> connectionSend (SshMsgDisconnect SshDiscProtocolError "" "")
       Just channel ->
         do result <- handleRequest request channelId channel
            when wantReply $
              connectionSend $
                if result
                  then SshMsgChannelSuccess (sshChannelRemote channel)
                  else SshMsgChannelFailure (sshChannelRemote channel)

handleRequest :: SshChannelRequest -> Word32 -> SshChannel -> Connection Bool
handleRequest request channelId channel =
  case request of
    SshChannelRequestPtyReq term widthChar heightChar _widthPixel _heightPixel _modes ->
      do let channel' = channel
               { sshChannelPty = Just (term, widthChar, heightChar)
               }
         connectionModifyChannels (Map.insert channelId channel')
         return True

    SshChannelRequestEnv name value ->
      do let channel' = channel
               { sshChannelEnv = (name,value) : sshChannelEnv channel
               }
         connectionModifyChannels (Map.insert channelId channel')
         return True

    SshChannelRequestShell ->
      do (client, state) <- Connection ask
         liftIO $
           do iStream <- makeInputStream  (channelRead channel)
              oStream <- makeOutputStream (channelWrite client state channelId channel)
              h <- streamPairToHandle iStream oStream
              _ <- forkIO (cOpenShell client h)
              return True
    SshChannelRequestExec _command        -> return False
    SshChannelRequestSubsystem _subsystem -> return False

channelRead channel =
  atomically $
    do buf <- readTVar (sshChannelData channel)
       when (L.null buf) retry
       writeTVar (sshChannelData channel) L.empty
       return (Just (L.toStrict buf))

channelWrite client state channelId channel Nothing =
  send client state (SshMsgChannelClose channelId)

channelWrite client state channelId channel (Just msg) =
  send client state (SshMsgChannelData (sshChannelRemote channel) msg)
