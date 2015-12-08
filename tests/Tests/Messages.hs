{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Tests.Messages where

import Network.SSH.Ciphers
import Network.SSH.Messages
import Network.SSH.Packet
import Network.SSH.Protocol

import           Control.Applicative ( (<$>), (<*>), pure )
import qualified Data.ByteString.Char8 as S
import           Data.ByteString.Short (ShortByteString)
import           Data.Monoid ((<>))
import           Data.Serialize ( Get, Putter, runGet, runPut )
import           Test.Framework ( Test, testGroup )
import           Test.Framework.Providers.QuickCheck2 ( testProperty )
import           Test.QuickCheck
                     ( Gen, Property, forAll, listOf, listOf1, elements
                     , counterexample, (===), vectorOf, arbitrary, oneof
                     , suchThat )


messageTests :: [Test]
messageTests  =
  [ testGroup "encode/decode"
      [ testProperty "SshIdent" $
        encodeDecode genSshIdent putSshIdent getSshIdent

      , testProperty "SshPubCert" $
        encodeDecode genSshPubCert putSshPubCert getSshPubCert

      , testProperty "SshSig" $
        encodeDecode genSshSig putSshSig getSshSig

      , testProperty "SshMsg" $
        encodeDecode genSshMsg putSshMsg getSshMsg

      ]
  ]

encodeDecode :: (Show a, Eq a) => Gen a -> Putter a -> Get a -> Property
encodeDecode gen render parse = forAll gen $ \ a ->
  case runGet parse (runPut (render a)) of
    Right a' -> a === a'
    Left err -> counterexample err False

{-
encodeDecodePacket :: (Show a, Eq a) => String -> Gen a -> Putter a -> Get a -> Test
encodeDecodePacket name gen render parse =
  testGroup name
    [ testProperty "unframed" (encodeDecode gen render parse)

    , testProperty "framed (no encryption)" $ forAll gen $ \ a ->
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
-}

ascii :: Gen Char
ascii  = elements $ concat [ [ 'a' .. 'z' ]
                           , [ 'A' .. 'Z' ]
                           , [ '0' .. '9' ]
                           , [ '.', '_'   ] ]

genSshIdent :: Gen SshIdent
genSshIdent  =
  do versionSuffix <- S.pack `fmap` listOf1 ascii
     comment       <- S.pack `fmap` listOf ascii
     -- Comments are optional in SSH version strings, but most be
     -- preceded by space if present.
     let comment' = if S.null comment then "" else " " <> comment
     let sshIdentString = "SSH-2.0-" <> versionSuffix <> comment'
     return SshIdent { .. }

kexAlgs :: NameList
kexAlgs  = [ "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1" ]

pubKeyAlgs :: NameList
pubKeyAlgs  = [ "ssh-dss"
              , "ssh-rsa"
              , "pgp-sign-rsa"
              , "pgp-sign-dss"
              ]


encAlgs :: NameList
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

macAlgs :: NameList
macAlgs  = [ "hmac-sha1"
           , "hmac-sha1-96"
           , "hmac-md5"
           , "hmac-md5-96"
           , "none"
           ]

compAlgs :: NameList
compAlgs  = [ "none", "zlib" ]

type Name = ShortByteString

genSshAlgs :: Gen Name -> Gen SshAlgs
genSshAlgs gen_name = SshAlgs <$> listOf gen_name <*> listOf gen_name

genSshDiscReason :: Gen SshDiscReason
genSshDiscReason  =
  elements [ SshDiscHostNotAllowed
           , SshDiscProtocolError
           , SshDiscKexFailed
           , SshDiscReserved
           , SshDiscMacError
           , SshDiscCompressionError
           , SshDiscServiceNotAvailable
           , SshDiscProtocolVersionNotSupported
           , SshDiscHostKeyNotVerifiable
           , SshDiscConnectionLost
           , SshDiscByApplication
           , SshDiscTooManyConnections
           , SshDiscAuthCancelledByUser
           , SshDiscNoMoreAuthMethodsAvailable
           , SshDiscIllegalUserName
           ]

genSshMsg :: Gen SshMsg
genSshMsg  =
  oneof [ do r <- genSshDiscReason
             d <- listOf ascii
             l <- listOf ascii
             return (SshMsgDisconnect r (S.pack d) (S.pack l))

        , do bytes <- listOf arbitrary
             return (SshMsgIgnore (S.pack bytes))

        , do sn <- arbitrary
             return (SshMsgUnimplemented sn)

        , do b <- arbitrary
             m <- listOf ascii
             l <- listOf ascii
             return (SshMsgDebug b (S.pack m) (S.pack l))

        , do svc <- genSshService
             return (SshMsgServiceRequest svc)

        , do svc <- genSshService
             return (SshMsgServiceAccept svc)

        , do kex <- genSshKeyExchange
             return (SshMsgKexInit kex)

        ,    return SshMsgNewKeys

        , do e <- genEncodedString
             return (SshMsgKexDhInit e)

        , do cert <- genSshPubCert
             f    <- genEncodedString
             sig  <- genSshSig
             return (SshMsgKexDhReply cert f sig)

        -- , SshMsgUserauthRequest
        -- , SshMsgUserauthFailure
        -- , SshMsgUserauthSuccess
        -- , SshMsgUserauthBanner
        -- , SshMsgGlobalRequest
        -- , SshMsgRequestSuccess
        -- , SshMsgRequestFailure
        -- , SshMsgChannelOpen
        -- , SshMsgChannelOpenConfirmation
        -- , SshMsgChannelOpenFailure
        -- , SshMsgChannelWindowAdjust
        -- , SshMsgChannelData
        -- , SshMsgChannelExtendedData
        -- , SshMsgChannelEof
        -- , SshMsgChannelClose
        -- , SshMsgChannelRequest
        -- , SshMsgChannelSuccess
        -- , SshMsgChannelFailure
        ]

genSshKeyExchange :: Gen SshProposal
genSshKeyExchange  =
  do sshProposalCookie    <- (SshCookie . S.pack) `fmap` vectorOf 16 arbitrary
     sshKexAlgs           <- listOf (elements kexAlgs)
     sshServerHostKeyAlgs <- listOf (elements pubKeyAlgs)
     sshEncAlgs  <- genSshAlgs (elements encAlgs)
     sshMacAlgs  <- genSshAlgs (elements macAlgs)
     sshCompAlgs <- genSshAlgs (elements compAlgs)
     let sshLanguages         = SshAlgs [] []
     sshFirstKexFollows <- arbitrary
     return SshProposal { .. }

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

genSshService :: Gen SshService
genSshService  =
  oneof [    pure SshUserAuth
        ,    pure SshConnection
        , do name <- listOf ascii
             pure (SshServiceOther (S.pack name))
        ]

genEncodedString :: Gen S.ByteString
genEncodedString = runPut . putString . S.pack <$> listOf arbitrary

{-
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
-}
