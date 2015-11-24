{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.Ciphers (
    Cipher(..)
  , cipherName
  , blockSize
  , crypt

  , cipher_none
  , cipher_aes128_cbc
  , cipher_aes128_ctr
  , cipher_aes128_gcm
  ) where

import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as S8
import qualified Data.ByteString.Lazy as L

import           Crypto.Error
import           Crypto.Cipher.AES
import qualified Crypto.Cipher.Types as Cipher

import           Data.Serialize
import           Data.Word
import           Data.ByteArray (convert)
import           Data.Monoid ((<>))

import           Network.SSH.Keys

-- | A streaming cipher.
data Cipher = forall st. Cipher
  { cipherName :: !S.ByteString
  , blockSize  :: !Int
  , paddingSize :: Int -> Int
  , cipherState :: st
  , getLength  :: st -> S.ByteString -> Int
  , crypt      :: st -> S.ByteString -> (st, S.ByteString)
  }

instance Show Cipher where
  show Cipher { .. } = S8.unpack cipherName

-- Supported Ciphers -----------------------------------------------------------

cipher_none :: Cipher
cipher_none  =
  Cipher { cipherName      = "none"
         , blockSize = 8
         , cipherState = ()
         , crypt = \_ x -> ((), x)
         , getLength = \_ -> either undefined fromIntegral . runGet getWord32be
         , paddingSize = roundUp 8
         }

cipher_aes128_cbc :: CipherKeys -> (Cipher,Cipher)
cipher_aes128_cbc CipherKeys { ckInitialIV = initial_iv, ckEncKey = key } =
  (enc_cipher, dec_cipher)
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
           , crypt       = enc
           , cipherState = iv0
           , getLength   = error "get length not supported for encryption"
           , paddingSize = roundUp 16
           }


  enc :: Cipher.IV AES128 -> S.ByteString -> (Cipher.IV AES128, S.ByteString)
  enc iv bytes = (iv', cipherText)
    where
    cipherText = Cipher.cbcEncrypt aesKey iv bytes
    Just iv' = Cipher.makeIV (S.drop (S.length bytes - ivSize) cipherText)

  dec_cipher =
    Cipher { cipherName  = "aes128-cbc"
           , blockSize   = ivSize
           , cipherState = iv0
           , crypt       = dec
           , paddingSize = roundUp 16
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

cipher_aes128_ctr :: CipherKeys -> (Cipher,Cipher)
cipher_aes128_ctr CipherKeys { ckInitialIV = initial_iv, ckEncKey = key } =
  (enc_cipher, dec_cipher)
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
           , crypt       = enc
           , cipherState = iv0
           , paddingSize = roundUp 16
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
           , paddingSize = roundUp 16
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

cipher_aes128_gcm :: CipherKeys -> (Cipher,Cipher) {- ^ encrypt, decrypt -}
cipher_aes128_gcm CipherKeys { ckInitialIV = initial_iv, ckEncKey = key } =
  (enc_cipher, dec_cipher)
  where

  aesKey :: AES128
  CryptoPassed aesKey = Cipher.cipherInit (L.toStrict (L.take 16 key))

  enc_cipher =
    Cipher { cipherName  = "aes128-gcm@openssh.com"
           , blockSize   = 16
           , crypt       = enc
           , cipherState = invocation_counter0
           , paddingSize = roundUp 16 . subtract 4
           , getLength   = undefined
           }

  dec_cipher =
    Cipher { cipherName  = "aes128-gcm@openssh.com"
           , blockSize   = 16
           , crypt       = dec
           , cipherState = invocation_counter0
           , paddingSize = roundUp 16 . subtract 4
           , getLength   = \_ block ->
                           (+)16 -- get the tag, too
                         $ either undefined fromIntegral
                         $ runGet getWord32be block
           }

  Right (fixed, invocation_counter0) =
           runGet (do x <- getWord32be
                      y <- getWord64be
                      return (x,y))
                  (L.toStrict (L.take 12 initial_iv))

  dec :: Word64 -> S.ByteString -> (Word64, S.ByteString) -- XXX: failable
  dec invocation_counter input_text = (invocation_counter+1, len_part<>plain_text)
    where
    (len_part,input_text1) = S.splitAt 4 input_text
    (cipher_text,auth_tag) = S.splitAt (S.length input_text1-16) input_text1

    Just plain_text =
      Cipher.aeadSimpleDecrypt
        (mkAead invocation_counter)
        len_part
        cipher_text
        (Cipher.AuthTag (convert auth_tag))

  enc :: Word64 -> S.ByteString -> (Word64, S.ByteString)
  enc invocation_counter input_text =
    (invocation_counter+1, len_part<>cipher_text<>convert auth_tag)
    where
    (len_part,plain_text) = S.splitAt 4 input_text

    (Cipher.AuthTag auth_tag, cipher_text) =
      Cipher.aeadSimpleEncrypt
        (mkAead invocation_counter)
        len_part
        plain_text
        16

  mkAead counter = aead
    where
    iv = runPut $ do putWord32be fixed
                     putWord64be counter

    CryptoPassed aead = Cipher.aeadInit Cipher.AEAD_GCM aesKey iv

roundUp ::
  Int {- ^ target multiple -} ->
  Int {- ^ body length     -} ->
  Int {- ^ padding length  -}
roundUp align bytesLen = paddingLen
  where
  bytesRem   = (4 + 1 + bytesLen) `mod` align

  -- number of bytes needed to align on block size
  alignBytes | bytesRem == 0 = 0
             | otherwise     = align - bytesRem

  paddingLen | alignBytes == 0 =              align
             | alignBytes <  4 = alignBytes + align
             | otherwise       = alignBytes

