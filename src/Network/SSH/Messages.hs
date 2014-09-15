{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.Messages where

import           Network.SSH.Protocol

import           Control.Applicative ( (<$>) )
import qualified Data.ByteString.Char8 as S
import           Data.Serialize
                     ( Get, Putter, Put, label, isolate, getBytes, putByteString
                     , putWord8, getWord8, getWord32be, putWord32be, runPut
                     , remaining )
import           Data.Word ( Word32 )


data SshMsgTag = SshMsgTagDisconnect
               | SshMsgTagIgnore
               | SshMsgTagUnimplemented
               | SshMsgTagDebug
               | SshMsgTagServiceRequest
               | SshMsgTagServiceAccept
               | SshMsgTagKexInit
               | SshMsgTagNewKeys
               | SshMsgTagKexDhInit
               | SshMsgTagKexDhReply
               | SshMsgTagUserAuthRequest
               | SshMsgTagUserAuthFailure
               | SshMsgTagUserAuthSuccess
               | SshMsgTagUserAuthBanner
               | SshMsgTagGlobalRequest
               | SshMsgTagRequestSuccess
               | SshMsgTagRequestFailure
               | SshMsgTagChannelOpen
               | SshMsgTagChannelOpenConfirmation
               | SshMsgTagChannelOpenFailure
               | SshMsgTagChannelWindowAdjust
               | SshMsgTagChannelData
               | SshMsgTagChannelExtendedData
               | SshMsgTagChannelEof
               | SshMsgTagChannelClose
               | SshMsgTagChannelRequest
               | SshMsgTagChannelSuccess
               | SshMsgTagChannelFailure
                 deriving (Show,Eq)

data SshMsg = SshMsgDisconnect SshDiscReason !S.ByteString !S.ByteString
            | SshMsgIgnore !S.ByteString
            | SshMsgUnimplemented !Word32
            | SshMsgDebug Bool !S.ByteString !S.ByteString
            | SshMsgServiceRequest SshService
            | SshMsgServiceAccept SshService
            | SshMsgKexInit SshKex
            | SshMsgNewKeys
            | SshMsgKexDhInit !Integer
            | SshMsgKexDhReply SshPubCert !Integer SshSig
            | SshMsgUserAuthRequest !S.ByteString SshService SshAuthMethod
            | SshMsgUserAuthFailure
            | SshMsgUserAuthSuccess
            | SshMsgUserAuthBanner
            | SshMsgGlobalRequest
            | SshMsgRequestSuccess
            | SshMsgRequestFailure
            | SshMsgChannelOpen
            | SshMsgChannelOpenConfirmation
            | SshMsgChannelOpenFailure
            | SshMsgChannelWindowAdjust
            | SshMsgChannelData
            | SshMsgChannelExtendedData
            | SshMsgChannelEof
            | SshMsgChannelClose
            | SshMsgChannelRequest
            | SshMsgChannelSuccess
            | SshMsgChannelFailure
              deriving (Show,Eq)

sshMsgTag :: SshMsg -> SshMsgTag
sshMsgTag msg = case msg of
  SshMsgDisconnect              {} -> SshMsgTagDisconnect
  SshMsgIgnore                  {} -> SshMsgTagIgnore
  SshMsgUnimplemented           {} -> SshMsgTagUnimplemented
  SshMsgDebug                   {} -> SshMsgTagDebug
  SshMsgServiceRequest          {} -> SshMsgTagServiceRequest
  SshMsgServiceAccept           {} -> SshMsgTagServiceAccept
  SshMsgKexInit                 {} -> SshMsgTagKexInit
  SshMsgNewKeys                 {} -> SshMsgTagNewKeys
  SshMsgKexDhInit               {} -> SshMsgTagKexDhInit
  SshMsgKexDhReply              {} -> SshMsgTagKexDhReply
  SshMsgUserAuthRequest         {} -> SshMsgTagUserAuthRequest
  SshMsgUserAuthFailure         {} -> SshMsgTagUserAuthFailure
  SshMsgUserAuthSuccess         {} -> SshMsgTagUserAuthSuccess
  SshMsgUserAuthBanner          {} -> SshMsgTagUserAuthBanner
  SshMsgGlobalRequest           {} -> SshMsgTagGlobalRequest
  SshMsgRequestSuccess          {} -> SshMsgTagRequestSuccess
  SshMsgRequestFailure          {} -> SshMsgTagRequestFailure
  SshMsgChannelOpen             {} -> SshMsgTagChannelOpen
  SshMsgChannelOpenConfirmation {} -> SshMsgTagChannelOpenConfirmation
  SshMsgChannelOpenFailure      {} -> SshMsgTagChannelOpenFailure
  SshMsgChannelWindowAdjust     {} -> SshMsgTagChannelWindowAdjust
  SshMsgChannelData             {} -> SshMsgTagChannelData
  SshMsgChannelExtendedData     {} -> SshMsgTagChannelExtendedData
  SshMsgChannelEof              {} -> SshMsgTagChannelEof
  SshMsgChannelClose            {} -> SshMsgTagChannelClose
  SshMsgChannelRequest          {} -> SshMsgTagChannelRequest
  SshMsgChannelSuccess          {} -> SshMsgTagChannelSuccess
  SshMsgChannelFailure          {} -> SshMsgTagChannelFailure

data SshService = SshUserAuth
                | SshConnection
                | SshServiceOther !S.ByteString
                  deriving (Show,Eq)

data SshDiscReason = SshDiscHostNotAllowed
                   | SshDiscProtocolError
                   | SshDiscKexFailed
                   | SshDiscReserved
                   | SshDiscMacError
                   | SshDiscCompressionError
                   | SshDiscServiceNotAvailable
                   | SshDiscProtocolVersionNotSupported
                   | SshDiscHostKeyNotVerifiable
                   | SshDiscConnectionLost
                   | SshDiscByApplication
                   | SshDiscTooManyConnections
                   | SshDiscAuthCancelledByUser
                   | SshDiscNoMoreAuthMethodsAvailable
                   | SshDiscIllegalUserName
                     deriving (Show,Eq)

-- | Always 16 bytes of random data.
newtype SshCookie = SshCookie S.ByteString
                    deriving (Show,Eq)

data SshAlgs = SshAlgs { sshClientToServer :: [S.ByteString]
                       , sshServerToClient :: [S.ByteString]
                       } deriving (Show,Eq)

data SshKex = SshKex { sshCookie            :: !SshCookie
                     , sshKexAlgs           :: [S.ByteString]
                     , sshServerHostKeyAlgs :: [S.ByteString]
                     , sshEncAlgs           :: !SshAlgs
                     , sshMacAlgs           :: !SshAlgs
                     , sshCompAlgs          :: !SshAlgs
                     , sshLanguages         :: !SshAlgs
                     , sshFirstKexFollows   :: Bool
                     } deriving (Show,Eq)

data SshPubCert = SshPubDss !Integer !Integer !Integer !Integer
                | SshPubRsa !Integer !Integer
                | SshPubOther !S.ByteString !S.ByteString
                  deriving (Show,Eq)

sshPubCertName :: SshPubCert -> S.ByteString
sshPubCertName SshPubDss {}      = "ssh-dss"
sshPubCertName SshPubRsa {}      = "ssh-rsa"
sshPubCertName (SshPubOther n _) = n

data SshSig = SshSigDss !Integer !Integer
            | SshSigRsa !S.ByteString
            | SshSigOther S.ByteString S.ByteString
              deriving (Show,Eq)

newtype SshSessionId = SshSessionId S.ByteString

data SshAuthMethod = SshAuthPublicKey Bool SshPubCert SshSig
                   | SshAuthPassword Bool !S.ByteString
                   | SshAuthHostBased
                   | SshAuthNone
                     deriving (Show,Eq)


-- Rendering -------------------------------------------------------------------

putSshMsgTag :: Putter SshMsgTag
putSshMsgTag msg = putWord8 $! case msg of
  SshMsgTagDisconnect              -> 1
  SshMsgTagIgnore                  -> 2
  SshMsgTagUnimplemented           -> 3
  SshMsgTagDebug                   -> 4
  SshMsgTagServiceRequest          -> 5
  SshMsgTagServiceAccept           -> 6
  SshMsgTagKexInit                 -> 20
  SshMsgTagNewKeys                 -> 21
  SshMsgTagKexDhInit               -> 30
  SshMsgTagKexDhReply              -> 31
  SshMsgTagUserAuthRequest         -> 50
  SshMsgTagUserAuthFailure         -> 51
  SshMsgTagUserAuthSuccess         -> 52
  SshMsgTagUserAuthBanner          -> 53
  SshMsgTagGlobalRequest           -> 80
  SshMsgTagRequestSuccess          -> 81
  SshMsgTagRequestFailure          -> 82
  SshMsgTagChannelOpen             -> 90
  SshMsgTagChannelOpenConfirmation -> 91
  SshMsgTagChannelOpenFailure      -> 92
  SshMsgTagChannelWindowAdjust     -> 93
  SshMsgTagChannelData             -> 94
  SshMsgTagChannelExtendedData     -> 95
  SshMsgTagChannelEof              -> 96
  SshMsgTagChannelClose            -> 97
  SshMsgTagChannelRequest          -> 98
  SshMsgTagChannelSuccess          -> 99
  SshMsgTagChannelFailure          -> 100

putSshMsg :: Putter SshMsg
putSshMsg msg =
  do putSshMsgTag (sshMsgTag msg)
     case msg of
       SshMsgDisconnect r d l           -> putDisconnect r d l
       SshMsgIgnore bytes               -> putByteString bytes
       SshMsgUnimplemented sn           -> putWord32be sn
       SshMsgDebug d m l                -> putDebug d m l
       SshMsgServiceRequest svc         -> putSshService svc
       SshMsgServiceAccept svc          -> putSshService svc
       SshMsgKexInit kex                -> putSshKex kex

       SshMsgNewKeys                    -> return ()
       SshMsgKexDhInit n                -> putMpInt n
       SshMsgKexDhReply c f s           -> putDhReply c f s

       SshMsgUserAuthRequest         {} -> fail "unimplemented"
       SshMsgUserAuthFailure         {} -> fail "unimplemented"
       SshMsgUserAuthSuccess         {} -> fail "unimplemented"
       SshMsgUserAuthBanner          {} -> fail "unimplemented"
       SshMsgGlobalRequest           {} -> fail "unimplemented"
       SshMsgRequestSuccess          {} -> fail "unimplemented"
       SshMsgRequestFailure          {} -> fail "unimplemented"
       SshMsgChannelOpen             {} -> fail "unimplemented"
       SshMsgChannelOpenConfirmation {} -> fail "unimplemented"
       SshMsgChannelOpenFailure      {} -> fail "unimplemented"
       SshMsgChannelWindowAdjust     {} -> fail "unimplemented"
       SshMsgChannelData             {} -> fail "unimplemented"
       SshMsgChannelExtendedData     {} -> fail "unimplemented"
       SshMsgChannelEof              {} -> fail "unimplemented"
       SshMsgChannelClose            {} -> fail "unimplemented"
       SshMsgChannelRequest          {} -> fail "unimplemented"
       SshMsgChannelSuccess          {} -> fail "unimplemented"
       SshMsgChannelFailure          {} -> fail "unimplemented"


putDebug :: Bool -> S.ByteString -> S.ByteString -> Put
putDebug d m l =
  do putBoolean d
     putString m
     putString l

putSshCookie :: Putter SshCookie
putSshCookie (SshCookie bytes) =
     putByteString bytes

putSshAlgs :: Putter SshAlgs
putSshAlgs SshAlgs { .. } =
  do putNameList sshClientToServer
     putNameList sshServerToClient

putSshKex :: Putter SshKex
putSshKex SshKex { .. } =
  do putSshCookie sshCookie
     putNameList sshKexAlgs
     putNameList sshServerHostKeyAlgs
     putSshAlgs sshEncAlgs
     putSshAlgs sshMacAlgs
     putSshAlgs sshCompAlgs
     putSshAlgs sshLanguages
     putBoolean sshFirstKexFollows

     -- RESERVED
     putWord32be 0

putSshPubCert :: Putter SshPubCert

putSshPubCert (SshPubDss p q g y) =
  do putString "ssh-dss"
     putMpInt p
     putMpInt q
     putMpInt g
     putMpInt y

putSshPubCert (SshPubRsa e n) =
  do putString "ssh-rsa"
     putMpInt e
     putMpInt n

putSshPubCert (SshPubOther name bytes) =
  do putString name
     putByteString bytes


putSshSig :: Putter SshSig

putSshSig (SshSigDss r s) =
  do putString "ssh-dss"
     putUnsigned 20 r
     putUnsigned 20 s

putSshSig (SshSigRsa s) =
  do putString "ssh-rsa"
     putString s

putSshSig (SshSigOther name bytes) =
  do putString name
     putByteString bytes

putDhReply :: SshPubCert -> Integer -> SshSig -> Put
putDhReply cert f sig =
  do putString (runPut (putSshPubCert cert))
     putMpInt f
     putString (runPut (putSshSig sig))

putSshDiscReason :: Putter SshDiscReason
putSshDiscReason r = putWord8 $! case r of
  SshDiscHostNotAllowed              -> 1
  SshDiscProtocolError               -> 2
  SshDiscKexFailed                   -> 3
  SshDiscReserved                    -> 4
  SshDiscMacError                    -> 5
  SshDiscCompressionError            -> 6
  SshDiscServiceNotAvailable         -> 7
  SshDiscProtocolVersionNotSupported -> 8
  SshDiscHostKeyNotVerifiable        -> 9
  SshDiscConnectionLost              -> 10
  SshDiscByApplication               -> 11
  SshDiscTooManyConnections          -> 12
  SshDiscAuthCancelledByUser         -> 13
  SshDiscNoMoreAuthMethodsAvailable  -> 14
  SshDiscIllegalUserName             -> 15

putDisconnect :: SshDiscReason -> S.ByteString -> S.ByteString -> Put
putDisconnect r msg lang =
  do putSshDiscReason r
     putString msg
     putString lang

putSshService :: Putter SshService
putSshService SshUserAuth            = putString "ssh-userauth"
putSshService SshConnection          = putString "ssh-connection"
putSshService (SshServiceOther name) = putString name


-- Parsing ---------------------------------------------------------------------

getSshMsgTag :: Get SshMsgTag
getSshMsgTag  = label "SshMsgTag" $
  do tag <- getWord8
     case tag of
       1   -> return SshMsgTagDisconnect
       2   -> return SshMsgTagIgnore
       3   -> return SshMsgTagUnimplemented
       4   -> return SshMsgTagDebug
       5   -> return SshMsgTagServiceRequest
       6   -> return SshMsgTagServiceAccept
       20  -> return SshMsgTagKexInit
       21  -> return SshMsgTagNewKeys
       30  -> return SshMsgTagKexDhInit
       31  -> return SshMsgTagKexDhReply
       50  -> return SshMsgTagUserAuthRequest
       51  -> return SshMsgTagUserAuthFailure
       52  -> return SshMsgTagUserAuthSuccess
       53  -> return SshMsgTagUserAuthBanner
       80  -> return SshMsgTagGlobalRequest
       81  -> return SshMsgTagRequestSuccess
       82  -> return SshMsgTagRequestFailure
       90  -> return SshMsgTagChannelOpen
       91  -> return SshMsgTagChannelOpenConfirmation
       92  -> return SshMsgTagChannelOpenFailure
       93  -> return SshMsgTagChannelWindowAdjust
       94  -> return SshMsgTagChannelData
       95  -> return SshMsgTagChannelExtendedData
       96  -> return SshMsgTagChannelEof
       97  -> return SshMsgTagChannelClose
       98  -> return SshMsgTagChannelRequest
       99  -> return SshMsgTagChannelSuccess
       100 -> return SshMsgTagChannelFailure
       _   -> fail ("Unknown message type: " ++ show tag)

getSshMsg :: Get SshMsg
getSshMsg  =
  do tag <- getSshMsgTag
     case tag of
       SshMsgTagDisconnect              -> getSshDisconnect
       SshMsgTagIgnore                  -> SshMsgIgnore <$> (getBytes =<< remaining)
       SshMsgTagUnimplemented           -> SshMsgUnimplemented <$> getWord32be
       SshMsgTagDebug                   -> getDebug
       SshMsgTagServiceRequest          -> SshMsgServiceRequest <$> getSshService
       SshMsgTagServiceAccept           -> SshMsgServiceAccept  <$> getSshService
       SshMsgTagKexInit                 -> SshMsgKexInit    <$> getSshKex
       SshMsgTagNewKeys                 -> return SshMsgNewKeys
       SshMsgTagKexDhInit               -> SshMsgKexDhInit  <$> getMpInt
       SshMsgTagKexDhReply              -> getDhReply
       SshMsgTagUserAuthRequest         -> getAuthRequest
       SshMsgTagUserAuthFailure         -> fail (show tag ++ ": not implemented")
       SshMsgTagUserAuthSuccess         -> fail (show tag ++ ": not implemented")
       SshMsgTagUserAuthBanner          -> fail (show tag ++ ": not implemented")
       SshMsgTagGlobalRequest           -> fail (show tag ++ ": not implemented")
       SshMsgTagRequestSuccess          -> fail (show tag ++ ": not implemented")
       SshMsgTagRequestFailure          -> fail (show tag ++ ": not implemented")
       SshMsgTagChannelOpen             -> fail (show tag ++ ": not implemented")
       SshMsgTagChannelOpenConfirmation -> fail (show tag ++ ": not implemented")
       SshMsgTagChannelOpenFailure      -> fail (show tag ++ ": not implemented")
       SshMsgTagChannelWindowAdjust     -> fail (show tag ++ ": not implemented")
       SshMsgTagChannelData             -> fail (show tag ++ ": not implemented")
       SshMsgTagChannelExtendedData     -> fail (show tag ++ ": not implemented")
       SshMsgTagChannelEof              -> fail (show tag ++ ": not implemented")
       SshMsgTagChannelClose            -> fail (show tag ++ ": not implemented")
       SshMsgTagChannelRequest          -> fail (show tag ++ ": not implemented")
       SshMsgTagChannelSuccess          -> fail (show tag ++ ": not implemented")
       SshMsgTagChannelFailure          -> fail (show tag ++ ": not implemented")

getSshDiscReason :: Get SshDiscReason
getSshDiscReason  = label "SshDiscReason" $
  do tag <- getWord8
     case tag of
       1  -> return SshDiscHostNotAllowed
       2  -> return SshDiscProtocolError
       3  -> return SshDiscKexFailed
       4  -> return SshDiscReserved
       5  -> return SshDiscMacError
       6  -> return SshDiscCompressionError
       7  -> return SshDiscServiceNotAvailable
       8  -> return SshDiscProtocolVersionNotSupported
       9  -> return SshDiscHostKeyNotVerifiable
       10 -> return SshDiscConnectionLost
       11 -> return SshDiscByApplication
       12 -> return SshDiscTooManyConnections
       13 -> return SshDiscAuthCancelledByUser
       14 -> return SshDiscNoMoreAuthMethodsAvailable
       15 -> return SshDiscIllegalUserName
       _  -> fail ("Unknown disconnection reason: " ++ show tag)

getSshDisconnect :: Get SshMsg
getSshDisconnect  =
  do reason <- getSshDiscReason
     desc   <- getString
     lang   <- getString
     return (SshMsgDisconnect reason desc lang)

getDebug :: Get SshMsg
getDebug  =
  do b <- getBoolean
     d <- getString
     l <- getString
     return (SshMsgDebug b d l)

getSshCookie :: Get SshCookie
getSshCookie  = SshCookie `fmap` getBytes 16

getSshAlgs :: Get SshAlgs
getSshAlgs  =
  do sshClientToServer <- getNameList
     sshServerToClient <- getNameList
     return SshAlgs { .. }

getSshKex :: Get SshKex
getSshKex  = label "SshKex" $
  do sshCookie            <- label "sshCookie"            getSshCookie
     sshKexAlgs           <- label "sshKexAlgs"           getNameList
     sshServerHostKeyAlgs <- label "sshServerHostKeyAlgs" getNameList
     sshEncAlgs           <- label "sshEncAlgs"           getSshAlgs
     sshMacAlgs           <- label "sshMacAlgs"           getSshAlgs
     sshCompAlgs          <- label "sshCompAlgs"          getSshAlgs
     sshLanguages         <- label "sshLanguages"         getSshAlgs
     sshFirstKexFollows   <- label "sshFirstKexFollows"   getBoolean

     -- RESERVED
     _ <- getWord32be

     return SshKex { .. }

getSshPubCert :: Get SshPubCert
getSshPubCert  = label "SshPubCert" $
  do name <- getString
     case name of
       "ssh-dss" ->
         do p         <- getMpInt
            q         <- getMpInt
            g         <- getMpInt
            y         <- getMpInt
            return (SshPubDss p q g y)

       "ssh-rsa" ->
         do e         <- getMpInt
            n         <- getMpInt
            return (SshPubRsa e n)

       _ ->
         do bytes <- getBytes =<< remaining
            return (SshPubOther name bytes)

getSshSig :: Get SshSig
getSshSig  = label "SshSig" $
  do name <- getString
     case name of
       "ssh-dss" ->
         do r <- getUnsigned (160 `div` 8)
            s <- getUnsigned (160 `div` 8)
            return (SshSigDss r s)

       "ssh-rsa" ->
         do s <- getString
            return (SshSigRsa s)

       _ ->
         do bytes <- getBytes =<< remaining
            return (SshSigOther name bytes)

getDhReply :: Get SshMsg
getDhReply  =
  do pubKeyLen <- getWord32be
     pubKey    <- isolate (fromIntegral pubKeyLen) getSshPubCert

     f         <- getMpInt

     sigLen    <- getWord32be
     sig       <- isolate (fromIntegral sigLen) getSshSig

     return (SshMsgKexDhReply pubKey f sig)

getSshService :: Get SshService
getSshService  =
  do service <- getString
     case service of
       "ssh-userauth"   -> return SshUserAuth
       "ssh-connection" -> return SshConnection
       _                -> return (SshServiceOther service)

getAuthRequest :: Get SshMsg
getAuthRequest  =
  do username    <- getString
     serviceName <- getSshService
     method      <- getAuthMethod
     return (SshMsgUserAuthRequest username serviceName method)

getAuthMethod :: Get SshAuthMethod
getAuthMethod  = label "SshAuthMethod" $
  do tag <- getString
     case tag of
       "publickey" ->
         do b <- getBoolean
            undefined

       "password" ->
            undefined

       "hostbased" ->
            undefined

       "none" ->
            return SshAuthNone

       _ ->
            fail ("Unknown auth method: " ++ S.unpack tag)
