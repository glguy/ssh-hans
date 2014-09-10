{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Tests.Transport where

import Network.SSH.Transport

import           Control.Applicative ( (<$>), (<*>) )
import qualified Data.ByteString.Char8 as S
import           Data.Serialize
                     ( Get, Putter, runGet, runPut, getByteString
                     , putByteString, get, put )
import           Test.Framework ( Test, testGroup )
import           Test.Framework.Providers.QuickCheck2 ( testProperty )
import           Test.QuickCheck
                     ( Gen, Property, forAll, listOf, listOf1, elements
                     , counterexample, (===), vectorOf, arbitrary )


transportTests =
  [ testGroup "encode/decode"
      [ testProperty "SshIdent" $
        encodeDecode gen_sshIdent putSshIdent getSshIdent

      , testProperty "SshPacket" $
        encodeDecode (S.pack `fmap` listOf1 ascii)
            (putSshPacket Nothing put) (fst `fmap` getSshPacket Nothing get)

      , testProperty "SshKeyExchange" $
        encodeDecode gen_sshKeyExchange putSshKeyExchange getSshKeyExchange

      , testProperty "framed SshKeyExchange" $
        encodeDecode gen_sshKeyExchange
            (putSshPacket Nothing putSshKeyExchange)
            (fst `fmap` getSshPacket Nothing getSshKeyExchange)

      , testProperty "SshKexDhInit" $
        encodeDecode genSshKexDhInit putSshKexDhInit getSshKexDhInit
      ]
  ]

encodeDecode :: (Show a, Eq a) => Gen a -> Putter a -> Get a -> Property
encodeDecode gen render parse = forAll gen $ \ a ->
  case runGet parse (runPut (render a)) of
    Right a' -> a === a'
    Left err -> counterexample err False

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
