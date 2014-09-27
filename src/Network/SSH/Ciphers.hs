{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.Ciphers (
    Cipher()
  , cipherName
  , blockSize
  , encrypt
  , decrypt

  , cipher_none
  , cipher_aes128_cbc
  ) where

import           Crypto.Cipher.AES128 ( AESKey128, AESKey192, AESKey256 )
import           Crypto.Classes.Exceptions
                     ( cbc, unCbc, blockSizeBytes, keyLengthBytes, buildKey )
import           Crypto.Types ( IV(..) )
import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L
import           Data.Tagged ( witness )


-- | A streaming cipher.
data Cipher = Cipher { cName      :: !S.ByteString
                     , cBlockSize :: !Int
                     , cEncrypt   :: S.ByteString -> (S.ByteString,Cipher)
                     }

instance Show Cipher where
  show Cipher { .. } = S8.unpack cName

cipherName :: Cipher -> S.ByteString
cipherName Cipher { .. } = cName

blockSize :: Cipher -> Int
blockSize Cipher { .. } = cBlockSize

encrypt :: Cipher -> S.ByteString -> (S.ByteString,Cipher)
encrypt Cipher { .. } = cEncrypt

decrypt :: Cipher -> S.ByteString -> (S.ByteString,Cipher)
decrypt Cipher { .. } = cEncrypt


-- Supported Ciphers -----------------------------------------------------------

cipher_none :: Cipher
cipher_none  =
  Cipher { cName      = "none"
         , cBlockSize = 8
         , cEncrypt   = \x -> (x,cipher_none)
         }

cipher_aes128_cbc :: L.ByteString -- ^ IV
                  -> L.ByteString -- ^ Key
                  -> (Cipher,Cipher)
cipher_aes128_cbc initial_iv key = (enc_cipher, dec_cipher)
  where

  aesKey :: AESKey128
  aesKey  = buildKey (L.toStrict (L.take (fromIntegral keySize) key))
  keySize = witness keyLengthBytes aesKey

  iv0     = IV (L.toStrict (L.take (fromIntegral ivSize) initial_iv))
  ivSize  = witness blockSizeBytes aesKey

  enc_cipher =
    Cipher { cName      = "aes128-cbc"
           , cBlockSize = ivSize
           , cEncrypt   = enc iv0
           }

  enc iv bytes = (cipherText, enc_cipher { cEncrypt = enc iv' })
    where
    (cipherText,iv') = cbc aesKey iv bytes

  dec_cipher =
    Cipher { cName      = "aes128-cbc"
           , cBlockSize = ivSize
           , cEncrypt   = dec iv0
           }

  dec iv cipherText = (bytes, enc_cipher { cEncrypt = dec iv' })
    where
    (bytes,iv') = unCbc aesKey iv cipherText
