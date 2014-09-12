{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Tests.Transport where

import Network.SSH.Ciphers
import Network.SSH.Transport

import           Control.Applicative ( (<$>), (<*>), pure )
import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.Serialize
                     ( Get, Putter, runGet, runPut, getByteString
                     , putByteString, get, put )
import           Test.Framework ( Test, testGroup )
import           Test.Framework.Providers.QuickCheck2 ( testProperty )
import           Test.QuickCheck
                     ( Gen, Property, forAll, listOf, listOf1, elements
                     , counterexample, (===), vectorOf, arbitrary, oneof
                     , suchThat )


transportTests =
  [ testGroup "encode/decode"
      [ testProperty "SshIdent" $
        encodeDecode gen_sshIdent putSshIdent getSshIdent

      , testProperty "mpint" $
        encodeDecode arbitrary putMpInt getMpInt

      , testProperty "SshPubCert" $
        encodeDecode genSshPubCert putSshPubCert getSshPubCert

      , testProperty "SshSig" $
        encodeDecode genSshSig putSshSig getSshSig

      , encodeDecodePacket "SshKeyExchange"    gen_sshKeyExchange   putSshKeyExchange    getSshKeyExchange
      , encodeDecodePacket "SshKexDhInit"      genSshKexDhInit      putSshKexDhInit      getSshKexDhInit
      , encodeDecodePacket "SshKexDhReply"     genSshKexDhReply     putSshKexDhReply     getSshKexDhReply
      , encodeDecodePacket "SshKexDhReply"     genSshKexDhReply     putSshKexDhReply     getSshKexDhReply
      , encodeDecodePacket "SshNewKeys"        (pure SshNewKeys)    putSshNewKeys        getSshNewKeys
      , encodeDecodePacket "SshServiceRequest" genSshServiceRequest putSshServiceRequest getSshServiceRequest
      ]
  ]

encodeDecode :: (Show a, Eq a) => Gen a -> Putter a -> Get a -> Property
encodeDecode gen render parse = forAll gen $ \ a ->
  case runGet parse (runPut (render a)) of
    Right a' -> a === a'
    Left err -> counterexample err False

encodeDecodePacket :: (Show a, Eq a) => String -> Gen a -> Putter a -> Get a -> Test
encodeDecodePacket name gen render parse =
  testGroup name
    [ testProperty "unframed" (encodeDecode gen render parse)

    , testProperty "framed (no encryption)" $ forAll gen $ \ a ->
      case runGet (getSshPacket cipher_none parse) (fst (putSshPacket cipher_none render a)) of
        Right (a',_,_) -> a === a'
        Left err       -> counterexample err False

    , testProperty "framed (aes128-cbc)" $
      forAll genKey $ \ (enc,dec) ->
      forAll gen    $ \ a         ->
      case runGet (getSshPacket dec parse) (fst (putSshPacket enc render a)) of
        Right (a',_,_) -> a === a'
        Left err       -> counterexample err False
    ]

ascii :: Gen Char
ascii  = elements $ concat [ [ 'a' .. 'z' ]
                           , [ 'A' .. 'Z' ]
                           , [ '0' .. '9' ]
                           , [ '.', '_'   ] ]

gen_sshIdent :: Gen SshIdent
gen_sshIdent  =
  do let sshProtoVersion = "2.0"
     sshSoftwareVersion <- S.pack `fmap` listOf1 ascii
     sshComments        <- S.pack `fmap` listOf ascii
     return SshIdent { .. }

kexAlgs :: [S.ByteString]
kexAlgs  = [ "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1" ]

pubKeyAlgs :: [S.ByteString]
pubKeyAlgs  = [ "ssh-dss"
              , "ssh-rsa"
              , "pgp-sign-rsa"
              , "pgp-sign-dss"
              ]


encAlgs :: [S.ByteString]
encAlgs  = [ "3des-cbc"
           , "blowfish-cbc"
           , "twofish256-cbc"
           , "twofish-cbc"
           , "twofish192-cbc"
           , "twofish128-cbc"
           , "aes256-cbc"
           , "aes192-cbc"
           , "aes128-cbc"
           , "serpent256-cbc"
           , "serpent192-cbc"
           , "serpent128-cbc"
           , "arcfour"
           , "idea-cbc"
           , "cast128-cbc"
           , "none"
           ]

macAlgs :: [S.ByteString]
macAlgs  = [ "hmac-sha1"
           , "hmac-sha1-96"
           , "hmac-md5"
           , "hmac-md5-96"
           , "none"
           ]

compAlgs :: [S.ByteString]
compAlgs  = [ "none", "zlib" ]

genSshAlgs :: Gen S.ByteString -> Gen SshAlgs
genSshAlgs gen_name = SshAlgs <$> listOf gen_name <*> listOf gen_name

gen_sshKeyExchange :: Gen SshKeyExchange
gen_sshKeyExchange  =
  do sshCookie <- (SshCookie . S.pack) `fmap` vectorOf 16 arbitrary
     sshKexAlgs <- listOf (elements kexAlgs)
     sshServerHostKeyAlgs <- listOf (elements pubKeyAlgs)
     sshEncAlgs  <- genSshAlgs (elements encAlgs)
     sshMacAlgs  <- genSshAlgs (elements macAlgs)
     sshCompAlgs <- genSshAlgs (elements compAlgs)
     let sshLanguages         = SshAlgs [] []
     sshFirstKexFollows <- arbitrary
     return SshKeyExchange { .. }


genSshKexDhInit :: Gen SshKexDhInit
genSshKexDhInit  =
  do sshE <- arbitrary
     return SshKexDhInit { .. }

genSshPubCert :: Gen SshPubCert
genSshPubCert  =
  oneof [ do p <- arbitrary
             q <- arbitrary
             g <- arbitrary
             y <- arbitrary
             return (SshPubDss p q g y)

        , do e <- arbitrary
             n <- arbitrary
             return (SshPubRsa e n)

        , do name  <- listOf1 ascii
             bytes <- listOf1 arbitrary
             return (SshPubOther (S.pack name) (S.pack bytes))
        ]

genSshSig :: Gen SshSig
genSshSig  =
  oneof [ do r <- arbitrary `suchThat` (>= 0)
             s <- arbitrary `suchThat` (>= 0)
             return (SshSigDss r s)

        , do s <- listOf1 arbitrary
             return (SshSigRsa (S.pack s))

        , do name  <- listOf1 ascii
             bytes <- listOf1 arbitrary
             return (SshSigOther (S.pack name) (S.pack bytes))
        ]

genSshKexDhReply :: Gen SshKexDhReply
genSshKexDhReply  =
  do sshHostPubKey <- genSshPubCert
     sshF          <- arbitrary
     sshHostSig    <- genSshSig
     return SshKexDhReply { .. }


genSshServiceRequest :: Gen SshServiceRequest
genSshServiceRequest  =
  do sshServiceName <- S.pack `fmap` listOf ascii
     return SshServiceRequest { .. }


-- | Generate an aes128-cbc cipher pair.
genKey :: Gen (Cipher,Cipher)
genKey  =
  do k  <- L.pack `fmap` vectorOf 16 arbitrary
     iv <- L.pack `fmap` vectorOf 16 arbitrary
     return (cipher_aes128_cbc k iv)
