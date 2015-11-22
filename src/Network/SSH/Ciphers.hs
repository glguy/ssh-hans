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

import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L

import           Crypto.Error
import           Crypto.Cipher.AES
import qualified Crypto.Cipher.Types as Cipher


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

  aesKey :: AES128
  CryptoPassed aesKey = Cipher.cipherInit (L.toStrict (L.take (fromIntegral keySize) key))
  Cipher.KeySizeFixed keySize = Cipher.cipherKeySize aesKey

  iv0    :: Cipher.IV AES128
  Just iv0 = Cipher.makeIV (L.toStrict (L.take (fromIntegral ivSize) initial_iv))
  ivSize  = Cipher.blockSize aesKey

  enc_cipher =
    Cipher { cName      = "aes128-cbc"
           , cBlockSize = ivSize
           , cEncrypt   = enc iv0
           }

  enc iv bytes
    | S.null bytes = (bytes, enc_cipher { cEncrypt = enc iv })
    | otherwise     = (cipherText, enc_cipher { cEncrypt = enc iv' })
    where
    cipherText = Cipher.cbcEncrypt aesKey iv bytes
    Just iv' = Cipher.makeIV (S.drop (S.length bytes - ivSize) cipherText)

  dec_cipher =
    Cipher { cName      = "aes128-cbc"
           , cBlockSize = ivSize
           , cEncrypt   = dec iv0
           }

  dec iv cipherText
    | S.null cipherText = (cipherText, enc_cipher { cEncrypt = dec iv })
    | otherwise         = (bytes, enc_cipher { cEncrypt = dec iv' })
    where
    bytes = Cipher.cbcDecrypt aesKey iv cipherText
    Just iv' = Cipher.makeIV
             $ S.drop (S.length cipherText - ivSize)
             $ cipherText
