{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.Server (

    Server(..)
  , Client(..)
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
import           TLS.DiffieHellman ( DiffieHellmanGroup(..), oakley2 )


-- Public API ------------------------------------------------------------------

data Server = Server { sAccept :: IO Client
                     }

data Client = Client { cGet   :: Int -> IO S.ByteString
                     , cPut   :: L.ByteString -> IO ()
                     , cClose :: IO ()
                     }

sshServer :: PrivateKey -> PublicKey -> Server -> IO ()
sshServer privKey pubKey sock = loop =<< newGenIO
  where
  loop g = do client <- sAccept sock
              let (g',gClient) = splitGen g
              _ <- forkIO $ sayHello gClient privKey pubKey client
                                `X.finally` cClose client
              loop g'

-- | Generates a 1024-bit RSA key pair.
genKeyPair :: IO (PrivateKey, PublicKey)
genKeyPair  =
  do gen <- newGenIO
     let (pub,priv,_) = generateKeyPair (gen :: CtrDRBG) 1024
         (p,q,_)      = generatePQ gen (1024 `div` 8)
         priv'        = priv { private_p = p, private_q = q }
     writeFile "server.priv" (show priv')
     writeFile "server.pub"  (show pub)
     return (priv', pub)


-- Server Internals ------------------------------------------------------------

data SshState = SshState { sshDecC  :: !(IORef Cipher) -- ^ Client decryption context
                         , sshEncS  :: !(IORef Cipher) -- ^ Server encryption context
                         , sshAuthC :: !(IORef Mac)    -- ^ Client authentication context
                         , sshAuthS :: !(IORef Mac)    -- ^ Server authentication context
                         }

initialState :: IO SshState
initialState  =
  do sshDecC  <- newIORef cipher_none
     sshEncS  <- newIORef cipher_none
     sshAuthC <- newIORef mac_none
     sshAuthS <- newIORef mac_none
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




parseFrom :: Client -> Get a -> IO (Either String a)
parseFrom handle body = go True (Partial (runGetPartial body))
  where
  go True  (Partial k) = do bytes <- cGet handle 1024
                            if S.null bytes
                               then fail "Client closed connection"
                               else go (S.length bytes == 1024) (k bytes)

  go False (Partial k) = go False (k S.empty)
  go _     (Done a _)  = return (Right a)
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
       res    <- parseFrom client (getSshPacket cipher mac getSshMsg)
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


greeting :: SshIdent
greeting  = SshIdent { sshProtoVersion    = "2.0"
                     , sshSoftwareVersion = "SSH_HaNS_1.0"
                     , sshComments        = ""
                     }

sayHello :: CtrDRBG -> PrivateKey -> PublicKey -> Client -> IO ()
sayHello gen priv pub client =
  do cPut client (runPutLazy (putSshIdent greeting))
     msg <- parseFrom client getSshIdent
     print msg
     case msg of
       Right v_c -> do print v_c
                       state <- initialState
                       startKex gen priv pub (sshDhHash v_c greeting) state client
       Left err  -> do print err
                       return ()


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
         -> SshState -> Client -> IO ()
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

startDh :: Client -> CtrDRBG -> PrivateKey -> PublicKey -> SshState
        -> (SshPubCert -> Integer -> Integer -> Integer -> S.ByteString)
        -> IO ()
startDh client gen priv @ PrivateKey { .. } pub @ PublicKey { .. } state mkHash =
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
              -> SshState -> Keys -> IO ()
getDhResponse client _gen _priv _pub _session_id state keys =
  do SshMsgNewKeys <- receive client state
     send client state SshMsgNewKeys

     transitionKeys keys state

     req <- receive client state
     case req of

       SshMsgServiceRequest SshUserAuth ->
         do send client state (SshMsgServiceAccept SshUserAuth)
            userReq <- receive client state
            print userReq

       _ ->
            send client state (SshMsgDisconnect SshDiscServiceNotAvailable "" "en-us")
