{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.UserAuth where

import Control.Applicative (liftA2)
import Network.SSH.Messages
import Network.SSH.Protocol
import Network.SSH.Keys
import Data.Serialize ( runGet, runPut )
import qualified Data.ByteString as S

import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import qualified Crypto.PubKey.ECC.ECDSA as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.Hash.Algorithms as Hash
import Crypto.Error


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
        RSA.verify (Just Hash.SHA1) (RSA.PublicKey (S.length s) n e) token s

      ("ecdsa-sha2-nistp256", SshPubEcDsaP256 pub, SshSigEcDsaP256 sig) ->
        do p <- nistp256PointFromBinary pub
           let p' = ECC.PublicKey (ECC.getCurveByName ECC.SEC_p256r1) p
           s <- eccSigFromBinary sig
           return (ECC.verify Hash.SHA256 p' s token)
        `catchCryptoFailure` \_ ->
           False

      ("ssh-ed25519", SshPubEd25519 pub, SshSigEd25519 sig) ->
        do p <- Ed25519.publicKey pub
           s <- Ed25519.signature sig
           return (Ed25519.verify p token s)
        `catchCryptoFailure` \_ ->
           False

      _ -> False

  where
  token = runPut $
    do putSessionId  sessionId
       putSshMsgTag  SshMsgTagUserAuthRequest
       putString     username
       putSshService service
       putString     "publickey"
       putBoolean    True
       putString     publicKeyAlgorithm
       putString     (runPut (putSshPubCert publicKey))

catchCryptoFailure :: CryptoFailable a -> (CryptoError -> a) -> a
catchCryptoFailure m h = onCryptoFailure h id m

eccSigFromBinary :: S.ByteString -> CryptoFailable ECC.Signature
eccSigFromBinary bs =
  case runGet (liftA2 ECC.Signature getMpInt getMpInt) bs of
    Left _ -> CryptoFailed CryptoError_SecretKeyStructureInvalid
    Right s -> CryptoPassed s
