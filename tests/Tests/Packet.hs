{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Tests.Packet where

import           Network.SSH.Ciphers
import           Network.SSH.Keys
import           Network.SSH.Mac
import           Network.SSH.Named
import           Network.SSH.Packet

import           Control.Applicative ( (<$>) )
import           Crypto.Random ( ChaChaDRG, drgNewTest )
import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.Serialize
                     ( runGet, getByteString, putByteString, remaining )
import           Data.Word
import           Test.Framework ( Test, testGroup )
import           Test.Framework.Providers.QuickCheck2 ( testProperty )
import           Test.QuickCheck
                     ( Gen, forAll, listOf , counterexample, (===), vectorOf
                     , arbitrary )

packetTests :: [Test]
packetTests =
  [ testGroup "encode/decode"
      [ testProperty "framed (no encryption)" $
        forAll genSeqNum $ \ seqNum ->
        forAll genDrg    $ \ drg    ->
        forAll gen       $ \ a      ->
        let (cipher,enc,dec) =
              (namedThing cipher_none,activateCipherE_none,activateCipherD_none)
            mac       = namedThing mac_none undefined
            (pkt,_,_) = putSshPacket seqNum cipher enc mac drg a
         in case runGet (getSshPacket seqNum cipher dec mac) (L.toStrict pkt) of
              Right (a',_) -> L.toStrict a === a'
              Left err     -> counterexample err False

      , testProperty "framed (aes128-cbc)" $
        forAll genCipher $ \ (cipher,enc,dec) ->
        forAll genSeqNum $ \ seqNum           ->
        forAll genDrg    $ \ drg              ->
        forAll gen       $ \ a                           ->
        let mac       = namedThing mac_none undefined
            (pkt,_,_) = putSshPacket seqNum cipher enc mac drg a
         in case runGet (getSshPacket seqNum cipher dec mac) (L.toStrict pkt) of
              Right (a',_) -> L.toStrict a === a'
              Left err     -> counterexample err False

      , testProperty "framed (aes128-cbc,hmac-sha1)" $
        forAll genCipher $ \ (cipher,enc,dec) ->
        forAll genMac    $ \ mac              ->
        forAll genSeqNum $ \ seqNum           ->
        forAll genDrg    $ \ drg              ->
        forAll gen       $ \ a                ->
        let (pkt,_,_) = putSshPacket seqNum cipher enc mac drg a
         in case runGet (getSshPacket seqNum cipher dec mac) (L.toStrict pkt) of
              Right (a',_) -> L.toStrict a === a'
              Left err     -> counterexample err False
      ]
  ]

  where
  gen :: Gen L.ByteString
  gen = L.pack <$> listOf arbitrary

-- | Generate an aes128-cbc cipher pair.
genCipher :: Gen (Cipher,ActiveCipher,ActiveCipher)
genCipher  =
  do k  <- L.pack `fmap` vectorOf 16 arbitrary
     iv <- L.pack `fmap` vectorOf 16 arbitrary
     let keys   = CipherKeys iv k
     let cipher = namedThing cipher_aes128_cbc
     return (cipher,activateCipherE keys cipher,activateCipherD keys cipher)

genMac :: Gen Mac
genMac  =
  do k <- L.pack `fmap` vectorOf 32 arbitrary
     return $ namedThing mac_hmac_sha1 k

genSeqNum :: Gen Word32
genSeqNum = arbitrary

genDrg :: Gen ChaChaDRG
genDrg = do
  [a,b,c,d,e] <- vectorOf 5 arbitrary
  return $ drgNewTest (a,b,c,d,e)

----------------------------------------------------------------
-- Orphan 'Show' instances for QuickCheck 'forAll'.

instance Show ChaChaDRG where
  show _ = "ChaChaDRG"

instance Show Mac where
  show _ = "Mac"

instance Show Cipher where
  show _ = "Cipher"

instance Show ActiveCipher where
  show _ = "ActiveCipher"
