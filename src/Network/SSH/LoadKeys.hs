{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.LoadKeys where

import           Control.Monad ((<=<), unless)
import           Data.ByteArray.Encoding (Base(Base64), convertFromBase)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as B8
import qualified Data.ByteString.Short as Short
import           Data.Serialize (runGet)

import qualified Crypto.PubKey.RSA as RSA

import           Network.SSH.Messages
import           Network.SSH.Named
import           Network.SSH.PrivateKeyFormat
import           Network.SSH.PubKey
import           Network.SSH.State

#if !MIN_VERSION_base(4,8,0)
import Control.Applicative ((<$>))
#endif

loadPublicKeys :: FilePath -> IO [SshPubCert]
loadPublicKeys fp =
  do keys <- B.readFile fp
     return [ key | line <- B8.lines keys
                  , key  <- case decodePublicKey line of
                              Right k -> [k]
                              Left  _ -> []
                  ]

decodePublicKey :: ByteString -> Either String SshPubCert
decodePublicKey xs =
  do (keyType, encoded) <- case B8.words xs of
                             x:y:_ -> return (x,y)
                             _     -> Left "Bad outer format"
     decoded <- convertFromBase Base64 encoded
     pubCert <- runGet getSshPubCert decoded
     unless (keyType == sshPubCertName pubCert) (Left "Mismatched key type")
     return pubCert

-- | Load private keys from file.
--
-- The keys file must be in OpenSSH format; see @:/server/README.md@.
--
-- The 'ServerCredential' here is a misnomer, since both clients and
-- servers use the same credential format.
loadPrivateKeys :: FilePath -> IO [ServerCredential]
loadPrivateKeys path =
  do res <- (extractPK <=< parsePrivateKeyFile) <$> B.readFile path
     case res of
       Left e -> fail ("Error loading server keys: " ++ e)
       Right pk -> return
                     [ Named (Short.toShort (sshPubCertName pub)) (pub, priv)
                     | (pub,priv,_comment) <- pk
                     ]

-- | Generate a random RSA 'ServerCredential' / named key pair.
generateRsaKeyPair :: IO ServerCredential
generateRsaKeyPair = do
  -- The '0x10001' exponent is suggested in the cryptonite
  -- documentation for 'RSA.generate'.
  (pub, priv) <- RSA.generate 256{-bytes-} 0x10001{-e-}
  let pub'  = SshPubRsa (RSA.public_e pub) (RSA.public_n pub)
  let priv' = PrivateRsa priv
  return (Named "ssh-rsa" (pub', priv'))
