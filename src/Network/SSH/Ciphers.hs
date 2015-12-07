{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ExistentialQuantification #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.Ciphers (
    Cipher(..)
  , ActiveCipher(..)
  , activateCipherE
  , activateCipherD

  , allCipher

  , cipher_none

  , cipher_3des_cbc

  , cipher_aes128_cbc
  , cipher_aes192_cbc
  , cipher_aes256_cbc

  , cipher_aes128_ctr
  , cipher_aes192_ctr
  , cipher_aes256_ctr

  , cipher_aes128_gcm
  , cipher_aes256_gcm

  , cipher_arcfour
  , cipher_arcfour128
  , cipher_arcfour256

  , cipher_blowfish_cbc

  , cipher_chacha20_poly1305
  ) where

import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L

import           Crypto.Error
import           Crypto.Cipher.AES
import           Crypto.Cipher.Blowfish
import           Crypto.Cipher.TripleDES
import qualified Crypto.Cipher.Types as Cipher
import qualified Crypto.Cipher.ChaCha as C
import qualified Crypto.Cipher.RC4 as RC4
import qualified Crypto.MAC.Poly1305 as Poly

import           Control.Applicative
import           Data.Serialize
import           Data.Word
import           Data.ByteArray (Bytes, constEq, convert)
import           Data.Monoid ((<>))

import           Network.SSH.Keys
import           Network.SSH.Named

-- | A streaming cipher.
data Cipher = forall st. Cipher
  { randomizePadding :: Bool
  , aeadMode         :: Bool
  , blockSize   :: !Int
  , paddingSize :: Int -> Int
  , cipherState :: CipherKeys -> st
  , getLength   :: st -> Word32 -> S.ByteString -> Int
  , encrypt     :: st -> Word32 -> S.ByteString -> (st, S.ByteString)
  , decrypt     :: st -> Word32 -> S.ByteString -> (st, S.ByteString)
  }

data ActiveCipher = ActiveCipher
  { acLength :: Word32 -> S.ByteString -> Int
  , acCrypt  :: Word32 -> S.ByteString -> (ActiveCipher, S.ByteString)
  }

activateCipherE :: CipherKeys -> Cipher -> ActiveCipher
activateCipherE keys Cipher{encrypt,getLength,cipherState} = aux (cipherState keys)
  where
  aux st = ActiveCipher
    { acLength = getLength st
    , acCrypt  = \seqNr input -> case encrypt st seqNr input of
                                   (st', output) -> (aux st', output)
    }

activateCipherD :: CipherKeys -> Cipher -> ActiveCipher
activateCipherD keys Cipher{decrypt,getLength,cipherState} = aux (cipherState keys)
  where
  aux st = ActiveCipher
    { acLength = getLength st
    , acCrypt  = \seqNr input -> case decrypt st seqNr input of
                                   (st', output) -> (aux st', output)
    }

allCipher :: [ Named Cipher ]
allCipher =
  [ cipher_none

  , cipher_3des_cbc

  , cipher_aes128_cbc
  , cipher_aes192_cbc
  , cipher_aes256_cbc

  , cipher_aes128_ctr
  , cipher_aes192_ctr
  , cipher_aes256_ctr

  , cipher_aes128_gcm
  , cipher_aes256_gcm

  , cipher_arcfour
  , cipher_arcfour128
  , cipher_arcfour256

  , cipher_blowfish_cbc

  , cipher_chacha20_poly1305
  ]

-- Supported Ciphers -----------------------------------------------------------

grab :: Int -> L.ByteString -> S.ByteString
grab n = L.toStrict . L.take (fromIntegral n)

cipher_none :: Named Cipher
cipher_none  = Named "none" $
  Cipher { randomizePadding = False
         , aeadMode         = False
         , blockSize = 8
         , cipherState = const ()
         , encrypt = \_ _ x -> ((), x)
         , decrypt = \_ _ x -> ((), x)
         , getLength = \_ _ -> either undefined fromIntegral . runGet getWord32be
         , paddingSize = roundUp 8
         }

data CipherName a = CipherName ShortByteString

-- | AES in Galois Counter Mode, 96-bit IV, 128-bit key, 128-bit MAC
--
-- RFC 5647: AES Galois Counter Mode for the Secure Shell Transport Layer Protocol
cipher_aes128_gcm :: Named Cipher
cipher_aes128_gcm = mk_cipher_gcm (CipherName "aes128-gcm@openssh.com" :: CipherName AES128)

-- | AES in Galois Counter Mode, 96-bit IV, 256-bit key, 128-bit MAC
--
-- RFC 5647: AES Galois Counter Mode for the Secure Shell Transport Layer Protocol
cipher_aes256_gcm :: Named Cipher
cipher_aes256_gcm = mk_cipher_gcm (CipherName "aes256-gcm@openssh.com" :: CipherName AES256)

-- | 3DES (EDE version) in cipher-block-chaining mode. 168-bit key
--
-- Weak cipher and also the current implementation is INSANELY slow!
cipher_3des_cbc :: Named Cipher
cipher_3des_cbc = mk_cipher_cbc (CipherName "3des-cbc" :: CipherName DES_EDE3)
{-# WARNING cipher_3des_cbc "3des-cbc is not only weak but it is very slow" #-}

-- | AES-128 cipher in cipher-block-chaining mode
cipher_aes128_cbc :: Named Cipher
cipher_aes128_cbc = mk_cipher_cbc (CipherName "aes128-cbc" :: CipherName AES128)

-- | AES-192 cipher in cipher-block-chaining mode
cipher_aes192_cbc :: Named Cipher
cipher_aes192_cbc = mk_cipher_cbc (CipherName "aes192-cbc" :: CipherName AES192)

-- | AES-256 cipher in cipher-block-chaining mode
cipher_aes256_cbc :: Named Cipher
cipher_aes256_cbc = mk_cipher_cbc (CipherName "aes256-cbc" :: CipherName AES256)

-- | Blowfish cipher in cipher-block-chaining mode with 128-bit key
cipher_blowfish_cbc :: Named Cipher
cipher_blowfish_cbc = mk_cipher_cbc (CipherName "blowfish-cbc" :: CipherName Blowfish)

-- | AES-128 cipher in couter-mode
cipher_aes128_ctr :: Named Cipher
cipher_aes128_ctr = mk_cipher_ctr (CipherName "aes128-ctr" :: CipherName AES128)

-- | AES-192 cipher in couter-mode
cipher_aes192_ctr :: Named Cipher
cipher_aes192_ctr = mk_cipher_ctr (CipherName "aes192-ctr" :: CipherName AES192)

-- | AES-256 cipher in couter-mode
cipher_aes256_ctr :: Named Cipher
cipher_aes256_ctr = mk_cipher_ctr (CipherName "aes256-ctr" :: CipherName AES256)

-- | RC4 stream cipher with 128-bit key
--
-- This mode does not drop initial bytes from the stream which can compromise
-- confidentiality over time.
cipher_arcfour :: Named Cipher
cipher_arcfour = mk_cipher_rc4 "arcfour" 16 0
{-# DEPRECATED cipher_arcfour "arcfour128 and arcfour256 mitigate weaknesses in arcfour" #-}

-- | RC4 stream cipher with 128-bit key
--
-- RFC 4345: Improved Arcfour Modes for the SSH Transport Layer Protocol
cipher_arcfour128 :: Named Cipher
cipher_arcfour128 = mk_cipher_rc4 "arcfour128" 16 1536

-- | RC4 stream cipher with 256-bit key
--
-- RFC 4345: Improved Arcfour Modes for the SSH Transport Layer Protocol
cipher_arcfour256 :: Named Cipher
cipher_arcfour256 = mk_cipher_rc4 "arcfour256" 32 1536

------------------------------------------------------------------------

mk_cipher_cbc ::
  forall cipher. Cipher.BlockCipher cipher =>
  CipherName cipher -> Named Cipher
mk_cipher_cbc (CipherName name)
  = Named name
  $
  let mkCipherState CipherKeys{ckInitialIV,ckEncKey}
        = (aesKey :: cipher, iv0)
        where
        CryptoPassed aesKey         = Cipher.cipherInit (grab keySize ckEncKey)
        Cipher.KeySizeFixed keySize = Cipher.cipherKeySize aesKey
        Just iv0                    = Cipher.makeIV (grab ivSize ckInitialIV)
        ivSize                      = Cipher.blockSize aesKey

      nextIV :: S.ByteString -> Cipher.IV cipher -> Cipher.IV cipher
      nextIV bytes old
        | S.null bytes = old
        | otherwise = case Cipher.makeIV (S.drop (S.length bytes - 16) bytes) of
                        Nothing -> error "nextIV: bad size"
                        Just new -> new

      enc (aesKey,iv) _ bytes =
        let cipherText = Cipher.cbcEncrypt aesKey iv bytes
        in ((aesKey,nextIV cipherText iv), cipherText)

      dec (aesKey,iv) _ cipherText =
        ( (aesKey,nextIV cipherText iv)
        , Cipher.cbcDecrypt aesKey iv cipherText)

  in Cipher
       { blockSize   = 16
       , randomizePadding = True
       , aeadMode         = False
       , encrypt     = enc
       , decrypt     = dec
       , cipherState = mkCipherState
       , paddingSize = roundUp 16
       , getLength   = \st seqNum block ->
                       either undefined fromIntegral
                     $ runGet getWord32be
                     $ snd -- ignore new state
                     $ dec st seqNum block
       }

mk_cipher_ctr ::
  forall cipher. Cipher.BlockCipher cipher =>
  CipherName cipher -> Named Cipher
mk_cipher_ctr (CipherName name) = Named name $

  let mkCipherState CipherKeys {ckInitialIV,ckEncKey} =
        (aesKey :: cipher, iv0 :: Cipher.IV cipher)
        where
        CryptoPassed aesKey         = Cipher.cipherInit (grab keySize ckEncKey)
        Cipher.KeySizeFixed keySize = Cipher.cipherKeySize aesKey
        Just iv0                    = Cipher.makeIV (grab ivSize ckInitialIV)
        ivSize                      = Cipher.blockSize aesKey

      enc (aesKey,iv) _ bytes = ((aesKey,iv'), cipherText)
        where
        cipherText = Cipher.ctrCombine aesKey iv bytes
        iv' = Cipher.ivAdd iv (S.length bytes `quot` 16)

  in Cipher
       { blockSize   = 16
       , randomizePadding = True
       , aeadMode         = False
       , encrypt     = enc
       , decrypt     = enc
       , cipherState = mkCipherState
       , paddingSize = roundUp 16
       , getLength   = \st seqNum block ->
                       either undefined fromIntegral
                     $ runGet getWord32be
                     $ snd -- ignore new state
                     $ enc st seqNum block
       }


mk_cipher_rc4 ::
  ShortByteString {- ^ cipher name -} ->
  Int {- ^ key size in bytes -} ->
  Int {- ^ stream discard size in bytes -} ->
  Named Cipher
mk_cipher_rc4 name keySize discardSize
  = Named name
  $
  let mkCipherState CipherKeys{ckEncKey} = st0
         where (st0,_::Bytes) = RC4.generate (RC4.initialize (grab keySize ckEncKey)) discardSize

      fakeBlockSize  = 8

  in Cipher
      { blockSize   = fakeBlockSize
      , randomizePadding = True
      , aeadMode         = False
      , encrypt     = \st _ -> RC4.combine st
      , decrypt     = \st _ -> RC4.combine st
      , cipherState = mkCipherState
      , paddingSize = roundUp fakeBlockSize
      , getLength   = \st _ block ->
                      either undefined fromIntegral
                    $ runGet getWord32be
                    $ snd -- ignore new state
                    $ RC4.combine st block
      }

data GcmState cipher = GcmState cipher ShortByteString !Word64

mk_cipher_gcm ::
  forall cipher. Cipher.BlockCipher cipher =>
  CipherName cipher -> Named Cipher
mk_cipher_gcm (CipherName name)
  = Named name $

  let lenLen, fixedLen, tagLen :: Int
      lenLen = 4
      fixedLen = 4
      tagLen = 16
      aesBlockSize = 16

      mkCipherState :: CipherKeys -> GcmState cipher
      mkCipherState CipherKeys { ckInitialIV, ckEncKey } = GcmState aesKey fixed counter0
        where
        aesKey :: cipher
        CryptoPassed aesKey = Cipher.cipherInit (grab keySize ckEncKey)
        Cipher.KeySizeFixed keySize = Cipher.cipherKeySize aesKey
        Right (fixed, counter0) =
          runGetLazy (liftA2 (,) (getShortByteString fixedLen) getWord64be) ckInitialIV

      computeNonce :: ShortByteString -> Word64 -> S.ByteString
      computeNonce fixed counter = runPut (putShortByteString fixed >> putWord64be counter)

      mkAead :: GcmState cipher -> Cipher.AEAD cipher
      mkAead (GcmState aesKey fixed counter)
        = throwCryptoError
        $ Cipher.aeadInit Cipher.AEAD_GCM aesKey
        $ computeNonce fixed counter

      advanceState :: GcmState a -> GcmState a
      advanceState (GcmState x y z) = GcmState x y (z+1)

      dec :: GcmState cipher -> Word32 -> S.ByteString -> (GcmState cipher, S.ByteString)
      dec st _ input_text = (advanceState st, len_part<>plain_text)
        where
        (len_part,(cipher_text,auth_tag))
             = fmap (S.splitAt (S.length input_text-(tagLen+lenLen)))
                    (S.splitAt lenLen input_text)

        Just plain_text =
          Cipher.aeadSimpleDecrypt (mkAead st) len_part cipher_text
            (Cipher.AuthTag (convert auth_tag))

      enc :: GcmState cipher -> Word32 -> S.ByteString -> (GcmState cipher, S.ByteString)
      enc st _ input_text =
        (advanceState st, S.concat [len_part,cipher_text,convert auth_tag])
        where
        (len_part,plain_text) = S.splitAt lenLen input_text

        (Cipher.AuthTag auth_tag, cipher_text) =
          Cipher.aeadSimpleEncrypt (mkAead st) len_part plain_text tagLen

  in Cipher
       { randomizePadding = True
       , aeadMode         = True
       , blockSize   = aesBlockSize
       , encrypt     = enc
       , decrypt     = dec
       , cipherState = mkCipherState
       , paddingSize = roundUp aesBlockSize . subtract lenLen
       , getLength   = \_ _ block ->
                       (+) tagLen -- get the tag, too
                     $ either undefined fromIntegral
                     $ runGet getWord32be block
       }


------------------------------------------------------------------------

-- | Implementation of the cipher-auth mode specified in PROTOCOL.chacha20poly1305
cipher_chacha20_poly1305 :: Named Cipher
cipher_chacha20_poly1305 = Named "chacha20-poly1305@openssh.com" $

  let mkCipherState CipherKeys{ckEncKey} = (payloadKey, lenKey)
        where
        (payloadKey', lenKey') = fmap (L.take chachaKeySize)
                                      (L.splitAt chachaKeySize ckEncKey)
        payloadKey = L.toStrict payloadKey'
        lenKey     = L.toStrict lenKey'

      rounds          = 20 -- chacha rounds
      chachaKeySize   = 32 -- key size for chacha algorithm
      polyKeySize     = 32 -- key size for poly1305 algorithm
      discardSize     = 32 -- aligns ciphertext to block counter 1
      lenLen          =  4 -- length of packet_len
      macLen          = 16 -- length of poly1305 mac

      mkNonce = runPut . putWord64be . fromIntegral

      getLen (_,lenKey) seqNr input_text = fromIntegral n + macLen
        where
        st = C.initialize rounds lenKey (mkNonce seqNr)
        Right n = runGet getWord32be
                $ fst
                $ C.combine st input_text

      dec ::
        (S.ByteString,S.ByteString)                 {- ^ payload key, length key  -} ->
        Word32                                      {- ^ sequence number          -} ->
        S.ByteString                                {- ^ len_ct || body_ct || mac -} ->
        ((S.ByteString,S.ByteString), S.ByteString) {- ^ dummy  || body_pt        -}
      dec st@(payloadKey,_) seqNr input_text
        | constEq computed_mac expected_mac = (st, dummy_body_pt)
        | otherwise                         = error "bad poly1305 tag"
        where
        nonce               = mkNonce seqNr

        dummy_len           = S.replicate lenLen 0
        dummy_body_pt       = dummy_len <> body_pt

        len_body_len        = S.length input_text - macLen
        (len_body_ct, expected_mac) = S.splitAt len_body_len input_text
        computed_mac        = Poly.auth polyKey len_body_ct

        body_ct             = S.drop lenLen len_body_ct
        st0                 = C.initialize rounds payloadKey nonce
        (polyKey,  st1)     = C.generate st0 polyKeySize :: (S.ByteString, C.State)
        (_discard, st2)     = C.generate st1 discardSize :: (S.ByteString, C.State)
        (body_pt , _  )     = C.combine  st2 body_ct     :: (S.ByteString, C.State)

      enc ::
        (S.ByteString,S.ByteString)                 {- ^ payload key, length key  -} ->
        Word32                                      {- ^ sequence number          -} ->
        S.ByteString                                {- ^ len_pt || body_pt        -} ->
        ((S.ByteString,S.ByteString), S.ByteString) {- ^ len_ct || body_ct || mac -}
      enc st@(payloadKey,lenKey) seqNr input_pt = (st, len_body_ct <> convert mac)
        where
        nonce               = mkNonce seqNr

        (len_pt, body_pt)   = S.splitAt lenLen input_pt
        (len_ct, _      )   = C.combine (C.initialize rounds lenKey nonce) len_pt

        len_body_ct         = len_ct <> body_ct
        mac                 = Poly.auth polyKey len_body_ct

        st0                 = C.initialize rounds payloadKey nonce
        (polyKey,  st1)     = C.generate st0 polyKeySize :: (S.ByteString, C.State)
        (_discard, st2)     = C.generate st1 discardSize :: (S.ByteString, C.State)
        (body_ct , _  )     = C.combine  st2 body_pt     :: (S.ByteString, C.State)

  in Cipher
      { blockSize   = lenLen -- bytes needed to decrypt length field
      , randomizePadding = True
      , aeadMode         = True
      , encrypt     = enc
      , decrypt     = dec
      , cipherState = mkCipherState
      , paddingSize = roundUp 8 . subtract lenLen
      , getLength   = getLen
      }

------------------------------------------------------------------------

roundUp ::
  Int {- ^ target multiple -} ->
  Int {- ^ body length     -} ->
  Int {- ^ padding length  -}
roundUp align bytesLen = paddingLen
  where
  bytesRem   = bytesLen `mod` align

  -- number of bytes needed to align on block size
  alignBytes | bytesRem == 0 = 0
             | otherwise     = align - bytesRem

  paddingLen | alignBytes == 0 =              align
             | alignBytes <  4 = alignBytes + align
             | otherwise       = alignBytes
