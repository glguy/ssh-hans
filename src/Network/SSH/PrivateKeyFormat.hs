{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.PrivateKeyFormat where

import Control.Applicative
import Control.Monad
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import Data.Serialize
import Data.ByteArray.Encoding
import Data.Word
import Network.SSH.Keys
import Network.SSH.Protocol
import Network.SSH.Messages
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.Ed25519 as Ed25519
import Crypto.Number.Basic (numBytes)
import Crypto.Error

data PrivateKeyFile = PrivateKeyFile
  { pkfCipherName :: S.ByteString
  , pkfKdfName    :: S.ByteString
  , pkfKdfOptions :: S.ByteString
  , pkfPublicKeys :: [S.ByteString]
  , pkfPrivateKeys :: S.ByteString
  }
  deriving Show

data PrivateKeyList = PrivateKeyList
  { checkInt :: Word32
  , privateKeys :: [(SshPubCert,PrivateKey,S.ByteString)]
  }

authMagic :: S.ByteString
authMagic = "openssh-key-v1\0"

armorHeader :: S.ByteString
armorHeader = "-----BEGIN OPENSSH PRIVATE KEY-----"

armorFooter :: S.ByteString
armorFooter = "-----END OPENSSH PRIVATE KEY-----"

getPrivateKeyFile :: Get PrivateKeyFile
getPrivateKeyFile =
  do authMagic1 <- label "magic" $ getByteString $ S.length authMagic
     unless (authMagic == authMagic1) (fail "bad magic value")
     pkfCipherName  <- label "cipherName" getString
     pkfKdfName     <- label "kdfName"    getString
     pkfKdfOptions  <- label "ldfOptions" getString
     n              <- label "number of keys" getWord32be
     pkfPublicKeys  <- replicateM (fromIntegral n) getString
     pkfPrivateKeys <- getString
     return PrivateKeyFile{..}

getPrivateKeyList :: Int -> Get PrivateKeyList
getPrivateKeyList n =
  do checkInt  <- getWord32be
     checkInt1 <- getWord32be
     unless (checkInt == checkInt1) (fail "incorrect decryption password")
     privateKeys <- replicateM n getPrivateKey
     return PrivateKeyList{..}

getPrivateKey :: Get (SshPubCert, PrivateKey, S.ByteString)
getPrivateKey =
  do pub  <- getSshPubCert
     priv <- case pub of
       SshPubRsa n e ->
         do let private_pub = RSA.PublicKey
                                { RSA.public_size = numBytes n
                                , RSA.public_e    = e
                                , RSA.public_n    = n }
            private_d <- getMpInt
            private_qinv <- getMpInt
            private_p <- getMpInt
            private_q <- getMpInt
            let private_dP = private_d `mod` (private_p-1)
                private_dQ = private_d `mod` (private_q-1)
            return (PrivateRsa RSA.PrivateKey{..})
       SshPubEd25519 {} ->
         do xs <- getString
            let (a,b) = S.splitAt 32 xs
            case liftA2 (,) (Ed25519.secretKey a) (Ed25519.publicKey b) of
              CryptoPassed (c,d) -> return (PrivateEd25519 c d)
              _                -> fail "bad ed25519 key"
       SshPubEcDsaP256{} ->
         PrivateEcdsa256 . ECDSA.PrivateKey (ECC.getCurveByName ECC.SEC_p256r1) <$> getMpInt
       SshPubEcDsaP384{} ->
         PrivateEcdsa384 . ECDSA.PrivateKey (ECC.getCurveByName ECC.SEC_p384r1) <$> getMpInt
       SshPubEcDsaP521{} ->
         PrivateEcdsa521 . ECDSA.PrivateKey (ECC.getCurveByName ECC.SEC_p521r1) <$> getMpInt
       _ -> fail "Unknown key type"
     comment <- getString
     let pub' = case pub of -- XXX is this right?
                  SshPubRsa n e -> SshPubRsa e n
                  _ -> pub
     return (pub', priv, comment)

removePadding :: S.ByteString -> Either String S.ByteString
removePadding xs
  | S.null xs            = Left "Attempted to remove padding from empty bytestring"
  | S.length xs < padLen = Left "Padding incorrect"
  | otherwise            = Right dat
  where
  padLen = fromIntegral (S.last xs) :: Int
  dat = S.take (S.length xs - padLen) xs

parsePrivateKeyFile :: S.ByteString -> Either String PrivateKeyFile
parsePrivateKeyFile xs =
  do step1 <- case dropWhile (/= armorHeader) (S8.lines xs) of
                []   -> Left "Missing private key header"
                _:ys -> Right ys
     step2 <- case break (== armorFooter) step1 of
              (_,[]) -> Left "Missing private key footer"
              (ys,_:_) -> Right ys
     step3 <- convertFromBase Base64 (S8.concat step2)

     runGet getPrivateKeyFile step3

extractPK :: PrivateKeyFile ->
  Either String [(SshPubCert,PrivateKey,S.ByteString)]
extractPK pkf =
  case pkfKdfName pkf of
    "none" -> go (pkfPrivateKeys pkf)
    name -> Left ("unknown kdf: " ++ S8.unpack name)
  where
  go privBytes =
    privateKeys <$>
    runGet (getPrivateKeyList (length (pkfPublicKeys pkf))) privBytes

demo fp = do
  Right pkf <- parsePrivateKeyFile <$> S.readFile fp
  print pkf
