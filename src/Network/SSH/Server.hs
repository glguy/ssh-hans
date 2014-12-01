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


-- Public API ------------------------------------------------------------------

data Server = Server { sAccept :: IO Client
                     }

data Client = Client { cGet         :: Int -> IO S.ByteString
                     , cPut         :: L.ByteString -> IO ()
                     , cClose       :: IO ()
                     , cAuthHandler :: L.ByteString -> SshAuthMethod -> IO Bool
                     }

sshServer :: SshIdent -> PrivateKey -> PublicKey -> Server -> IO ()
sshServer ident privKey pubKey sock = loop =<< newGenIO
  where
  loop g = do client <- sAccept sock
              let (g',gClient) = splitGen g
              _ <- forkIO $ sayHello ident gClient privKey pubKey client
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
                               else go True (k bytes)

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

sayHello :: SshIdent -> CtrDRBG -> PrivateKey -> PublicKey -> Client -> IO ()
sayHello ident gen priv pub client =
  do cPut client (runPutLazy (putSshIdent ident))
     state <- initialState
     msg   <- parseFrom client (sshBuf state) getSshIdent
     print msg
     case msg of
       Right v_c -> do print v_c
                       startKex gen priv pub (sshDhHash v_c ident) state client
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

     let notAvailable = send client state
                      $ SshMsgDisconnect SshDiscServiceNotAvailable "" "en-us"

     req <- receive client state
     case req of

       SshMsgServiceRequest SshUserAuth ->
         do send client state (SshMsgServiceAccept SshUserAuth)
            userReq <- receive client state
            case userReq of

              SshMsgUserAuthRequest user svc method ->
                do _ <- cAuthHandler client (L.fromStrict user) method
                   return ()

              _ -> notAvailable

       _ -> notAvailable
