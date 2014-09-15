{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Tests.Packet where

import Network.SSH.Ciphers
import Network.SSH.Mac
import Network.SSH.Packet

import           Control.Applicative ( (<$>) )
import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.Serialize
                     ( runGet, getByteString, putByteString, remaining )
import           Test.Framework ( Test, testGroup )
import           Test.Framework.Providers.QuickCheck2 ( testProperty )
import           Test.QuickCheck
                     ( Gen, forAll, listOf , counterexample, (===), vectorOf
                     , arbitrary )

packetTests :: [Test]
packetTests =
  [ testGroup "encode/decode"
      [ testProperty "framed (no encryption)" $ forAll gen $ \ a ->
        let (pkt,_,_) = putSshPacket cipher_none mac_none (render a)
         in case runGet (getSshPacket cipher_none mac_none parse) (L.toStrict pkt) of
              Right (a',_,_) -> a === a'
              Left err       -> counterexample err False

      , testProperty "framed (aes128-cbc)" $
        forAll genCipher $ \ (enc,dec) ->
        forAll gen       $ \ a         ->
        let (pkt,_,_) = putSshPacket enc mac_none (render a)
         in case runGet (getSshPacket dec mac_none parse) (L.toStrict pkt) of
              Right (a',_,_) -> a === a'
              Left err       -> counterexample err False

      , testProperty "framed (aes128-cbc,hmac-sha1)" $
        forAll genCipher $ \ (enc,dec) ->
        forAll genMac    $ \ mac       ->
        forAll gen       $ \ a         ->
        let (pkt,_,_) = putSshPacket enc mac (render a)
         in case runGet (getSshPacket dec mac parse) (L.toStrict pkt) of
              Right (a',_,_) -> a === a'
              Left err       -> counterexample err False
      ]
  ]

  where

  gen    = S.pack <$> listOf arbitrary
  parse  = getByteString =<< remaining
  render = putByteString

-- | Generate an aes128-cbc cipher pair.
genCipher :: Gen (Cipher,Cipher)
genCipher  =
  do k  <- L.pack `fmap` vectorOf 16 arbitrary
     iv <- L.pack `fmap` vectorOf 16 arbitrary
     return (cipher_aes128_cbc k iv)

genMac :: Gen Mac
genMac  =
  do k <- L.pack `fmap` vectorOf 32 arbitrary
     return (mac_hmac_sha1 k)
