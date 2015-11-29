{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.PubKey where

import           Control.Applicative
import qualified Data.ByteString as S
import           Data.Serialize (Get, Putter, runGet, runPut)

import           Crypto.Error
import           Crypto.Number.Basic (numBytes)
import           Crypto.Number.Serialize (os2ip, i2ospOf_)
import qualified Crypto.Hash as Hash
import qualified Crypto.PubKey.DSA as DSA
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.ECC.Prim as ECC
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.Ed25519 as Ed25519
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.RSA.PKCS15 as RSA
import           Data.ByteArray (convert)

import           Network.SSH.Messages
import           Network.SSH.Protocol

data PrivateKey
  = PrivateEd25519 Ed25519.SecretKey Ed25519.PublicKey
  | PrivateRsa     RSA.PrivateKey
  | PrivateDsa     DSA.PrivateKey
  | PrivateEcdsa256 ECDSA.PrivateKey
  | PrivateEcdsa384 ECDSA.PrivateKey
  | PrivateEcdsa521 ECDSA.PrivateKey

pointFromBytes :: ECC.Curve -> S.ByteString -> CryptoFailable ECC.Point
pointFromBytes curve bs =
  case S.uncons bs of
    Just (4{-no compression-}, bs1)
     | let n = curveSizeBytes curve
     , 2 * n == S.length bs1 ->

        case S.splitAt n bs1 of
          (xbytes, ybytes) ->
             let p = ECC.Point (os2ip xbytes) (os2ip ybytes)
             in if ECC.isPointValid curve p
                 then CryptoPassed p
                 else CryptoFailed CryptoError_PublicKeySizeInvalid

    _ -> CryptoFailed CryptoError_PublicKeySizeInvalid

pointToBytes :: ECC.Curve -> ECC.Point -> S.ByteString
pointToBytes _ ECC.PointO = S.singleton 0
pointToBytes curve (ECC.Point x y) =
  S.concat ["\4" , i2ospOf_ n x, i2ospOf_ n y]
  where
  n = curveSizeBytes curve

curveSizeBytes :: ECC.Curve -> Int
curveSizeBytes = numBytes . ECC.ecc_n . ECC.common_curve

sign :: PrivateKey -> SshSessionId -> IO SshSig
sign pk (SshSessionId token) =
  case pk of

    PrivateRsa priv ->
      do result <- RSA.signSafer (Just Hash.SHA1) priv token
         case result of
           Right x -> return (SshSigRsa x)
           Left e -> fail (show e)

    PrivateDsa priv ->
      do sig <- DSA.sign priv Hash.SHA1 token
         return (SshSigDss (DSA.sign_r sig) (DSA.sign_s sig))

    PrivateEd25519 priv pub ->
      return (SshSigEd25519 (convert (Ed25519.sign priv pub token)))

    PrivateEcdsa256 priv ->
      SshSigEcDsaP256 . eccSigToBinary <$> ECDSA.sign priv Hash.SHA256 token

    PrivateEcdsa384 priv ->
      SshSigEcDsaP384 . eccSigToBinary <$> ECDSA.sign priv Hash.SHA384 token

    PrivateEcdsa521 priv ->
      SshSigEcDsaP521 . eccSigToBinary <$> ECDSA.sign priv Hash.SHA512 token

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
        RSA.verify (Just Hash.SHA1) (RSA.PublicKey (numBytes n) n e) token s

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
     let p' = ECDSA.PublicKey curve p
     s <- eccSigFromBinary sig
     return (ECDSA.verify hash p' s token)
  `catchCryptoFailure` \_ ->
     False

catchCryptoFailure :: CryptoFailable a -> (CryptoError -> a) -> a
catchCryptoFailure m h = onCryptoFailure h id m

eccSigFromBinary :: S.ByteString -> CryptoFailable ECDSA.Signature
eccSigFromBinary bs =
  case runGet getEcdsaSig bs of
    Left _ -> CryptoFailed CryptoError_SecretKeyStructureInvalid
    Right s -> CryptoPassed s

eccSigToBinary :: ECDSA.Signature -> S.ByteString
eccSigToBinary = runPut . putEcdsaSig

getEcdsaSig :: Get ECDSA.Signature
getEcdsaSig = liftA2 ECDSA.Signature getMpInt getMpInt

putEcdsaSig :: Putter ECDSA.Signature
putEcdsaSig (ECDSA.Signature r s) = putMpInt r >> putMpInt s
