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
import Data.Foldable (traverse_)
import Network.SSH.PubKey
import Network.SSH.Protocol
import Network.SSH.Messages
import qualified Crypto.PubKey.ECC.Types as ECC
import qualified Crypto.PubKey.ECC.ECDSA as ECDSA
import qualified Crypto.PubKey.RSA as RSA
import qualified Crypto.PubKey.DSA as DSA
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
     pkfPublicKeys  <- label "public keys" (replicateM (fromIntegral n) getString)
     pkfPrivateKeys <- label "private key blob" getString
     return PrivateKeyFile{..}

putPrivateKeyFile :: Putter PrivateKeyFile
putPrivateKeyFile pkf =
  do putByteString authMagic
     putString "none"
     putString "none"
     putString ""
     putWord32be (fromIntegral (length (pkfPublicKeys pkf)))
     traverse_ putString (pkfPublicKeys pkf)
     putString (pkfPrivateKeys pkf)

getPrivateKeyList :: Int -> Get PrivateKeyList
getPrivateKeyList n =
  do checkInt  <- getWord32be
     checkInt1 <- getWord32be
     unless (checkInt == checkInt1) (fail "incorrect decryption password")
     privateKeys <- replicateM n getPrivateKey
     return PrivateKeyList{..}

-- putPrivateKeyList :: Putter PrivateKeyList
-- putPrivateKeyList pkl =
--   do putWord32be (checkInt pkl)
--      traverse_ putPrivateKey (privateKeys pkl)

getPrivateKey :: Get (SshPubCert, PrivateKey, S.ByteString)
getPrivateKey = label "private key" $
  do ty <- label "private key type" getString
     (pub,priv) <- case ty of
       "ssh-rsa" -> label "rsa key" $
         do public_n       <- getMpInt
            public_e       <- getMpInt
            private_d      <- getMpInt
            private_qinv   <- getMpInt
            private_p      <- getMpInt
            private_q      <- getMpInt
            let private_dP  = private_d `mod` (private_p-1)
                private_dQ  = private_d `mod` (private_q-1)
                public_size = numBytes public_n
                private_pub = RSA.PublicKey{..}
            return (SshPubRsa public_e public_n, PrivateRsa RSA.PrivateKey{..})

       "ssh-dss" -> label "dsa key" $
         do params_p  <- getMpInt
            params_q  <- getMpInt
            params_g  <- getMpInt
            public_y  <- getMpInt
            private_x <- getMpInt
            let private_params = DSA.Params{..}
            return ( SshPubDss params_p params_q params_g public_y
                   , PrivateDsa DSA.PrivateKey{..} )

       "ssh-ed25519" -> label "ed25519 key" $
         do pub1 <- getString
            priv <- getString
            let (sec,pub2) = S.splitAt 32 priv
            guard (pub1 == pub2)
            case liftA2 (,) (Ed25519.secretKey sec) (Ed25519.publicKey pub1) of
              CryptoPassed (c,d) -> return (SshPubEd25519 pub1, PrivateEd25519 c d)
              _                  -> fail "bad ed25519 key"

       "ecdsa-sha2-nistp256" -> label "ecdsap256 key" $
         do (pub, priv) <- getEccPubPriv "nistp256" (ECC.getCurveByName ECC.SEC_p256r1)
            return (SshPubEcDsaP256 pub, PrivateEcdsa256 priv)
       "ecdsa-sha2-nistp384" -> label "ecdsap384 key" $
         do (pub, priv) <- getEccPubPriv "nistp384" (ECC.getCurveByName ECC.SEC_p384r1)
            return (SshPubEcDsaP384 pub, PrivateEcdsa384 priv)
       "ecdsa-sha2-nistp521" -> label "ecdsap521 key" $
         do (pub, priv) <- getEccPubPriv "nistp521" (ECC.getCurveByName ECC.SEC_p521r1)
            return (SshPubEcDsaP521 pub, PrivateEcdsa521 priv)

       _ -> fail "Unknown key type"

     comment <- getString

     return (pub, priv, comment)

getEccPubPriv :: S.ByteString -> ECC.Curve -> Get (S.ByteString, ECDSA.PrivateKey)
getEccPubPriv name curve =
  do name1      <- getString
     guard (name == name1)
     pubBytes   <- getString
     priv       <- getMpInt
     case pointFromBytes curve pubBytes of
       CryptoFailed e -> fail (show e)
       CryptoPassed _ -> return ()
     return (pubBytes, ECDSA.PrivateKey curve priv)

removePadding :: S.ByteString -> Either String S.ByteString
removePadding xs
  | S.null xs            = Left "Attempted to remove padding from empty bytestring"
  | S.length xs < padLen = Left "Padding incorrect"
  | otherwise            = Right dat
  where
  padLen = fromIntegral (S.last xs) :: Int
  dat = S.take (S.length xs - padLen) xs

addPadding :: S.ByteString -> S.ByteString
addPadding xs = xs `S.append` pad
  where
  padLen = 16 - S.length xs `mod` 16
  pad = S.pack [1..fromIntegral padLen]

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

-- | Merge multiple new OpenSSH private key files into a single one
-- The file format as defined supports this though openssh doesn't
-- appear to actually handle it correctly.
mergePrivateKeys :: [S.ByteString] -> Either String S.ByteString
mergePrivateKeys xs =
  do pkfs1 <- traverse parsePrivateKeyFile xs
     pkf   <- case pkfs1 of
                [] -> Left "No private key files"
                pkf:_ -> return pkf

     priv:privs <- traverse (removePadding . pkfPrivateKeys) pkfs1

     let discardCheckBytes = S.drop 8
         pkf' = pkf { pkfPublicKeys = pkfPublicKeys =<< pkfs1
                    , pkfPrivateKeys = addPadding
                                     $ priv
                            `S.append` S.concat (map discardCheckBytes privs)
                    }

         lineLen = 70 -- to match openssh's behavior
         dataLine = convertToBase Base64 (runPut (putPrivateKeyFile pkf'))

     return $ S8.unlines $ [ armorHeader ]
                        ++ chunks lineLen dataLine
                        ++ [ armorFooter ]




chunks :: Int -> S.ByteString -> [S.ByteString]
chunks n xs
  | S.length xs <= n = [xs]
  | otherwise = a : chunks n b
  where
  (a,b) = S.splitAt n xs
