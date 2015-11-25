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
import qualified Crypto.PubKey.DSA as DSA
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
        RSA.verify (Just Hash.SHA1) (RSA.PublicKey (octetSize n) n e) token s

      ("ssh-dss", SshPubDss p q g y, SshSigDss r s) ->
        let params = DSA.Params { DSA.params_p = p
                                , DSA.params_q = q
                                , DSA.params_g = g }
            pub = DSA.PublicKey { DSA.public_params = params
                                , DSA.public_y = y }
            sig = DSA.Signature { DSA.sign_r = r
                                , DSA.sign_s = s }
         in DSA.verify Hash.SHA1 pub sig token

      ("ecdsa-sha2-nistp256", SshPubEcDsaP256 pub, SshSigEcDsaP256 sig) ->
           ecdsaAuth ECC.SEC_p256r1 Hash.SHA256 pub sig token

      ("ecdsa-sha2-nistp384", SshPubEcDsaP384 pub, SshSigEcDsaP384 sig) ->
           ecdsaAuth ECC.SEC_p384r1 Hash.SHA384 pub sig token

      ("ecdsa-sha2-nistp521", SshPubEcDsaP521 pub, SshSigEcDsaP521 sig) ->
           ecdsaAuth ECC.SEC_p521r1 Hash.SHA512 pub sig token

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

-- | The length of the modulus n in octets is the integer k satisfying
-- 2^(8(k-1)) <= n < 2^(8k)
octetSize :: Integer -> Int
octetSize = aux 0
  where
  aux acc n
    | n <= 0 = acc
    | otherwise = aux (acc+1) (n`quot`256)

ecdsaAuth ::
  Hash.HashAlgorithm h =>
  ECC.CurveName {- ^ curve used for signature       -} ->
  h             {- ^ hash used in verification      -} ->
  S.ByteString  {- ^ uncompressed encoding of point -} ->
  S.ByteString  {- ^ encoded signature              -} ->
  S.ByteString  {- ^ message to verify              -} ->
  Bool          {- ^ success when true -}
ecdsaAuth curveName hash pub sig token =
  do let curve = ECC.getCurveByName curveName
     p <- pointFromBytes curve pub
     let p' = ECC.PublicKey curve p
     s <- eccSigFromBinary sig
     return (ECC.verify hash p' s token)
  `catchCryptoFailure` \_ ->
     False

catchCryptoFailure :: CryptoFailable a -> (CryptoError -> a) -> a
catchCryptoFailure m h = onCryptoFailure h id m

eccSigFromBinary :: S.ByteString -> CryptoFailable ECC.Signature
eccSigFromBinary bs =
  case runGet (liftA2 ECC.Signature getMpInt getMpInt) bs of
    Left _ -> CryptoFailed CryptoError_SecretKeyStructureInvalid
    Right s -> CryptoPassed s
