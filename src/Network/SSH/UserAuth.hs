{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.UserAuth where

import Network.SSH.Messages
import Network.SSH.Protocol
import Data.Serialize ( runPut )
import qualified Codec.Crypto.RSA.Pure as RSA
import qualified Crypto.Types.PubKey.RSA as RSA
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L

verifyPubKeyAuthentication ::
  SshSessionId {- ^ session ID           -} ->
  S.ByteString {- ^ username             -} ->
  SshService   {- ^ initial service      -} ->
  S.ByteString {- ^ public key algorithm -} ->
  SshPubCert   {- ^ public key           -} ->
  SshSig       {- ^ signature            -} ->
  Bool
verifyPubKeyAuthentication
  sessionId username service publicKeyAlgorithm publicKey signature =
    case (publicKeyAlgorithm, publicKey, signature) of
      ("ssh-rsa", SshPubRsa e n, SshSigRsa s) ->
         case rsaVerify
                (RSA.PublicKey (S.length s) n e)
                (L.fromStrict token)
                (L.fromStrict s) of
           Right r -> r
           Left  _ -> False
      _ -> False

  where
  rsaVerify = RSA.rsassa_pkcs1_v1_5_verify RSA.hashSHA1

  token = runPut $
    do putSessionId  sessionId
       putSshMsgTag  SshMsgTagUserAuthRequest
       putString     username
       putSshService service
       putString     "publickey"
       putBoolean    True
       putString     publicKeyAlgorithm
       putString     (runPut (putSshPubCert publicKey))
