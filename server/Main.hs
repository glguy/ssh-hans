{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main where

import           Network.SSH.Transport

import           Control.Concurrent ( forkIO )
import qualified Control.Exception as X
import           Control.Monad ( forever )
import           Control.Monad.CryptoRandom ( crandomR )
import           Crypto.Classes.Exceptions ( newGenIO, genBytes, splitGen )
import           Crypto.Random.DRBG ( CtrDRBG )
import           Crypto.Types.PubKey.RSA ( PublicKey(..), PrivateKey(..) )
import           Codec.Crypto.RSA.Exceptions
                     ( generateKeyPair, modular_exponentiation
                     , rsassa_pkcs1_v1_5_sign, hashSHA1, generatePQ
                     , HashInfo(..) )
import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.Serialize ( Get, Put, runPut, runGet, runGetPartial, Result(..), getBytes, remaining )
import           System.Directory ( doesFileExist )
import           System.IO ( Handle, hClose )
import           TLS.DiffieHellman ( DiffieHellmanGroup(..), oakley2 )
import           Network ( PortID(..), withSocketsDo, listenOn, accept )


main = withSocketsDo $
  do gen  <- newGenIO
     sock <- listenOn (PortNumber 2200)

     (gen',privKey,pubKey) <- loadKeys gen

     server gen' privKey pubKey sock

loadKeys gen =
  do privExists <- doesFileExist "server.priv"
     pubExists  <- doesFileExist "server.pub"

     if privExists && pubExists
        then do priv <- readFile "server.priv"
                pub  <- readFile "server.pub"
                return (gen, read priv, read pub) -- icky

        else do let (pub,priv,gen') = generateKeyPair gen 1024
                    (p,q,_)         = generatePQ gen (1024 `div` 8)
                    priv'           = priv { private_p = p, private_q = q }
                writeFile "server.priv" (show priv')
                writeFile "server.pub"  (show pub)
                return (gen', priv', pub)

server gen privKey pubKey sock = loop gen
  where
  loop g = do (client,host,port) <- accept sock
              putStrLn ("Got a client from: " ++ host ++ ":" ++ show port)
              let (g',gClient) = splitGen gen
              _ <- forkIO (sayHello gClient privKey pubKey client `X.finally` hClose client)
              loop g'



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

type PartialHash = Put

sayHello :: CtrDRBG -> PrivateKey -> PublicKey -> Handle -> IO ()
sayHello gen priv pub client =
  do S.hPutStr client (runPut (putSshIdent greeting))
     msg <- parseFrom client getSshIdent
     print msg
     case msg of
       Right v_c -> do print v_c
                       startKex gen priv pub (sshDhHash v_c greeting) client
       Left err    -> return ()


supportedKex :: SshCookie -> SshKeyExchange
supportedKex sshCookie =
  SshKeyExchange { sshKexAlgs           = [ "diffie-hellman-group1-sha1" ]
                 , sshServerHostKeyAlgs = [ "ssh-rsa" ]
                 , sshEncAlgs           = SshAlgs [ "3des-cbc" ] [ "3des-cbc" ]
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

startKex gen priv pub mkHash client =
  do let (cookie,gen') = newCookie gen
         i_s           = supportedKex cookie
     S.hPutStr client (runPut (putSshPacket Nothing putSshKeyExchange i_s))

     msg <- parseFrom client (getSshPacket Nothing getSshKeyExchange)
     case msg of
       Right (i_c,_mac) -> do print i_c
                              startDh client gen priv pub (mkHash i_c i_s)
       Left err  ->    print err

startDh client gen priv @ PrivateKey { .. } pub @ PublicKey { .. } mkHash =
  do msg <- parseFrom client (getSshPacket Nothing getSshKexDhInit)
     case msg of

       Right (SshKexDhInit { .. }, _) ->
         do let Right (y,gen') = crandomR (1,private_q) gen
                f              = modular_exponentiation (dhgG oakley2) y (dhgP oakley2)
                k              = modular_exponentiation sshE y (dhgP oakley2)
                cert           = SshPubRsa public_e public_n
                hash           = mkHash cert sshE f k
                h              = hashFunction hashSHA1 (L.fromStrict hash)
                sig            = rsassa_pkcs1_v1_5_sign hashSHA1 priv h
            S.hPutStr client $ runPut
                             $ putSshPacket Nothing putSshKexDhReply
                             $ SshKexDhReply { sshHostPubKey = cert
                                             , sshF          = f
                                             , sshHostSig    = SshSigRsa (L.toStrict sig) }

            getDhResponse client gen' priv pub

       Left err -> print err


getDhResponse client gen priv pub =
  do msg <- parseFrom client (getSshPacket Nothing (getBytes =<< remaining))
     print msg
