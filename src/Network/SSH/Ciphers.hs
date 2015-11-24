{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.Ciphers (
    Cipher(..)
  , cipherName
  , blockSize
  , crypt

  , cipher_none_dec
  , cipher_none_enc
  , cipher_aes128_cbc
  , cipher_aes128_ctr
  ) where

import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L

import           Crypto.Error
import           Crypto.Cipher.AES
import qualified Crypto.Cipher.Types as Cipher

import           Data.Serialize ( putWord32be, runPut, getWord32be, runGet )

-- | A streaming cipher.
data Cipher = forall st. Cipher
  { cipherName :: !S.ByteString
  , blockSize  :: !Int
  , cipherState :: st
  , getLength  :: st -> S.ByteString -> Int
  , crypt      :: st -> S.ByteString -> (st, S.ByteString)
  }

instance Show Cipher where
  show Cipher { .. } = S8.unpack cipherName

addLength :: S.ByteString -> S.ByteString
addLength bytes = S.append (runPut (putWord32be (fromIntegral (S.length bytes))))
                           bytes

-- Supported Ciphers -----------------------------------------------------------

cipher_none_enc :: Cipher
cipher_none_enc  =
  Cipher { cipherName      = "none"
         , blockSize = 8
         , cipherState = ()
         , crypt = \_ x -> ((), addLength x)
         , getLength = \_ -> either undefined fromIntegral . runGet getWord32be
         }

cipher_none_dec :: Cipher
cipher_none_dec  =
  Cipher { cipherName      = "none"
         , blockSize = 8
         , cipherState = ()
         , crypt = \_ x -> ((), x)
         , getLength = \_ -> either undefined fromIntegral . runGet getWord32be
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
    Cipher { cipherName  = "aes128-cbc"
           , blockSize   = ivSize
           , crypt       = \iv bytes -> enc iv (addLength bytes)
           , cipherState = iv0
           , getLength   = error "get length not supported for encryption"
           }


  enc iv bytes = (iv', cipherText)
    where
    cipherText = Cipher.cbcEncrypt aesKey iv bytes
    Just iv' = Cipher.makeIV (S.drop (S.length bytes - ivSize) cipherText)

  dec_cipher =
    Cipher { cipherName  = "aes128-cbc"
           , blockSize   = ivSize
           , cipherState = iv0
           , crypt       = dec
           , getLength   = \st block ->
                           either undefined fromIntegral
                         $ runGet getWord32be
                         $ snd -- ignore new state
                         $ dec st block
           }

  dec :: Cipher.IV AES128 -> S.ByteString -> (Cipher.IV AES128, S.ByteString)
  dec iv cipherText = (iv', bytes)
    where
    bytes = Cipher.cbcDecrypt aesKey iv cipherText
    Just iv' = Cipher.makeIV
             $ S.drop (S.length cipherText - ivSize)
             $ cipherText

cipher_aes128_ctr :: L.ByteString -- ^ IV
                  -> L.ByteString -- ^ Key
                  -> (Cipher,Cipher)
cipher_aes128_ctr initial_iv key = (enc_cipher, dec_cipher)
  where

  aesKey :: AES128
  CryptoPassed aesKey = Cipher.cipherInit (L.toStrict (L.take (fromIntegral keySize) key))
  Cipher.KeySizeFixed keySize = Cipher.cipherKeySize aesKey

  iv0    :: Cipher.IV AES128
  Just iv0 = Cipher.makeIV (L.toStrict (L.take (fromIntegral ivSize) initial_iv))
  ivSize  = Cipher.blockSize aesKey

  enc_cipher =
    Cipher { cipherName       = "aes128-ctr"
           , blockSize  = ivSize
           , crypt       = \st bytes -> enc st (addLength bytes)
           , cipherState = iv0
           , getLength   = \st block ->
                           either undefined fromIntegral
                         $ runGet getWord32be
                         $ snd -- ignore new state
                         $ enc st block
           }

  dec_cipher =
    Cipher { cipherName       = "aes128-ctr"
           , blockSize  = ivSize
           , crypt       = enc
           , cipherState = iv0
           , getLength   = \st block ->
                           either undefined fromIntegral
                         $ runGet getWord32be
                         $ snd -- ignore new state
                         $ enc st block
           }

  enc iv bytes = (iv', cipherText)
    where
    cipherText = Cipher.ctrCombine aesKey iv bytes
    iv' = Cipher.ivAdd iv
        $ S.length bytes `quot` ivSize
