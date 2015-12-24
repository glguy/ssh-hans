{-# LANGUAGE CPP #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.Messages where

import           Network.SSH.Protocol


import           Control.Monad ( when )
import           Data.ByteString.Short (ShortByteString)
import qualified Data.ByteString.Char8 as S
import           Data.ByteString.Lazy ()
import           Data.Serialize
                     ( Get, Putter, Put, label, isolate, getBytes, putByteString
                     , putWord8, getWord8, getWord32be, putWord32be, runPut
                     , remaining )
import           Data.Maybe ( isJust, fromJust )
import           Data.Word ( Word32 )

#if !MIN_VERSION_base(4,8,0)
import           Control.Applicative ( (<$>), (<*>) )
#endif

{-
 Transport layer protocol:

      1 to 19    Transport layer generic (e.g., disconnect, ignore,
                 debug, etc.)
      20 to 29   Algorithm negotiation
      30 to 49   Key exchange method specific (numbers can be reused
                 for different authentication methods)

   User authentication protocol:

      50 to 59   User authentication generic
      60 to 79   User authentication method specific (numbers can be
                 reused for different authentication methods)

   Connection protocol:

      80 to 89   Connection protocol generic
      90 to 127  Channel related messages

   Reserved for client protocols:

      128 to 191 Reserved

   Local extensions:

      192 to 255 Local extensions
-}

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
               | SshMsgTagUserAuthPkOk
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

            -- Shared secret establishment and server authentication.
            | SshMsgKexInit SshProposal
            | SshMsgNewKeys
            | SshMsgKexDhInit !S.ByteString
            | SshMsgKexDhReply SshPubCert !S.ByteString SshSig

            -- Client authentication.
            | SshMsgUserAuthRequest !S.ByteString SshService SshAuthMethod
            | SshMsgUserAuthFailure
                 [ShortByteString] -- Supported methods
                 Bool           -- Partial success
            | SshMsgUserAuthPkOk
                 !S.ByteString -- key algorithm
                 !SshPubCert   -- key blob
            | SshMsgUserAuthSuccess
            | SshMsgUserAuthBanner !S.ByteString !S.ByteString

            -- Channel independent global requests and replies.
            | SshMsgGlobalRequest !S.ByteString !Bool !S.ByteString
            | SshMsgRequestSuccess !S.ByteString
            | SshMsgRequestFailure

            -- Channel creation requests and replies.
            | SshMsgChannelOpen !SshChannelType !Word32 !Word32 !Word32
            | SshMsgChannelOpenConfirmation !Word32 !Word32 !Word32 !Word32
            | SshMsgChannelOpenFailure !Word32 !SshOpenFailure !S.ByteString !S.ByteString

            -- Channel-specific data-related messages.
            | SshMsgChannelWindowAdjust !Word32 !Word32
            | SshMsgChannelData !Word32 !S.ByteString
            | SshMsgChannelExtendedData !Word32 !Word32 !S.ByteString
            | SshMsgChannelEof !Word32
            | SshMsgChannelClose !Word32

            -- Channel-specific requests and replies.
            | SshMsgChannelRequest !SshChannelRequest !Word32 !Bool
            | SshMsgChannelSuccess !Word32
            | SshMsgChannelFailure !Word32
              deriving (Show,Eq)


openFailureToCode :: SshOpenFailure -> Word32
openFailureToCode x =
  case x of
    SshOpenAdministrativelyProhibited -> 1
    SshOpenConnectFailed              -> 2
    SshOpenUnknownChannelType         -> 3
    SshOpenResourceShortage           -> 4

codeToOpenFailure :: Word32 -> Maybe SshOpenFailure
codeToOpenFailure x =
  case x of
    1 -> Just SshOpenAdministrativelyProhibited
    2 -> Just SshOpenConnectFailed
    3 -> Just SshOpenUnknownChannelType
    4 -> Just SshOpenResourceShortage
    _ -> Nothing

data SshOpenFailure
  = SshOpenAdministrativelyProhibited
  | SshOpenConnectFailed
  | SshOpenUnknownChannelType
  | SshOpenResourceShortage
  deriving (Read, Show, Eq, Ord)

data SshChannelRequestTag
  = SshChannelRequestTagPtyReq
  | SshChannelRequestTagX11Req
  | SshChannelRequestTagEnv
  | SshChannelRequestTagShell
  | SshChannelRequestTagExec
  | SshChannelRequestTagSubsystem
  | SshChannelRequestTagWindowChange
  | SshChannelRequestTagXonXoff
  | SshChannelRequestTagSignal
  | SshChannelRequestTagExitStatus
  | SshChannelRequestTagExitSignal
  deriving (Read,Show,Eq,Ord)

data SshChannelRequest
  = SshChannelRequestPtyReq S.ByteString SshWindowSize S.ByteString
  | SshChannelRequestEnv !S.ByteString !S.ByteString
  | SshChannelRequestShell
  | SshChannelRequestExec !S.ByteString
  | SshChannelRequestSubsystem !S.ByteString
  | SshChannelRequestWindowChange !SshWindowSize
  deriving (Read,Show,Eq,Ord)

sshChannelRequestTag :: SshChannelRequest -> SshChannelRequestTag
sshChannelRequestTag request = case request of
  SshChannelRequestPtyReq {}       -> SshChannelRequestTagPtyReq
  SshChannelRequestEnv {}          -> SshChannelRequestTagEnv
  SshChannelRequestShell {}        -> SshChannelRequestTagShell
  SshChannelRequestExec {}         -> SshChannelRequestTagExec
  SshChannelRequestSubsystem {}    -> SshChannelRequestTagSubsystem
  SshChannelRequestWindowChange {} -> SshChannelRequestTagWindowChange

data SshWindowSize = SshWindowSize
  { sshWsCols, sshWsRows, sshWsX, sshWsY :: !Word32 }
  deriving (Read, Show, Ord, Eq)

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
  SshMsgUserAuthPkOk            {} -> SshMsgTagUserAuthPkOk
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

data SshDiscReason = SshDiscNoReason
                   | SshDiscHostNotAllowed
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
  deriving (Eq,Show,Read)

type NameList = [ShortByteString]

data SshAlgs = SshAlgs
  { sshClientToServer :: NameList
  , sshServerToClient :: NameList
  } deriving (Eq,Show,Read)

data SshProposal = SshProposal
  { sshProposalCookie    :: !SshCookie
  , sshKexAlgs           :: NameList
  , sshServerHostKeyAlgs :: NameList
  , sshEncAlgs           :: !SshAlgs
  , sshMacAlgs           :: !SshAlgs
  , sshCompAlgs          :: !SshAlgs
  , sshLanguages         :: !SshAlgs
  , sshFirstKexFollows   :: Bool
  } deriving (Eq,Show,Read)

data SshPubCert
  = SshPubDss !Integer !Integer !Integer !Integer -- ^ p q g y
  | SshPubRsa !Integer !Integer -- ^ e n
  | SshPubEcDsaP256 !S.ByteString
  | SshPubEcDsaP384 !S.ByteString
  | SshPubEcDsaP521 !S.ByteString
  | SshPubEd25519 !S.ByteString
  | SshPubOther !S.ByteString !S.ByteString
  deriving (Eq,Show,Read)

sshPubCertName :: SshPubCert -> S.ByteString
sshPubCertName SshPubDss       {} = "ssh-dss"
sshPubCertName SshPubRsa       {} = "ssh-rsa"
sshPubCertName SshPubEcDsaP256 {} = "ecdsa-sha2-nistp256"
sshPubCertName SshPubEcDsaP384 {} = "ecdsa-sha2-nistp384"
sshPubCertName SshPubEcDsaP521 {} = "ecdsa-sha2-nistp521"
sshPubCertName SshPubEd25519   {} = "ssh-ed25519"
sshPubCertName (SshPubOther n _) = n

data SshSig
  = SshSigDss !Integer !Integer -- ^ r s
  | SshSigRsa !S.ByteString
  | SshSigEcDsaP256 !S.ByteString
  | SshSigEcDsaP384 !S.ByteString
  | SshSigEcDsaP521 !S.ByteString
  | SshSigEd25519 !S.ByteString
  | SshSigOther S.ByteString S.ByteString
  deriving (Eq,Show,Read)

newtype SshSessionId = SshSessionId S.ByteString

data SshAuthMethod = SshAuthPublicKey S.ByteString SshPubCert (Maybe SshSig)
                   | SshAuthPassword !S.ByteString (Maybe S.ByteString) {- ^ optional new password -}
                   | SshAuthHostBased !S.ByteString !S.ByteString !S.ByteString !S.ByteString !S.ByteString
                   | SshAuthNone
                     deriving (Show,Eq)

data SshChannelTypeTag
  = SshChannelTypeTagSession
  | SshChannelTypeTagX11
  | SshChannelTypeTagForwardedTcpIp
  | SshChannelTypeTagDirectTcpIp
  deriving (Read,Show,Eq,Ord)

data SshChannelType
  = SshChannelTypeSession
  | SshChannelTypeX11 S.ByteString Word32
  | SshChannelTypeForwardedTcpIp S.ByteString Word32 S.ByteString Word32
  | SshChannelTypeDirectTcpIp S.ByteString Word32 S.ByteString Word32
  deriving (Read,Show,Eq,Ord)

sshChannelTypeTag :: SshChannelType -> SshChannelTypeTag
sshChannelTypeTag tp = case tp of
  SshChannelTypeSession          -> SshChannelTypeTagSession
  SshChannelTypeX11{}            -> SshChannelTypeTagX11
  SshChannelTypeForwardedTcpIp{} -> SshChannelTypeTagForwardedTcpIp
  SshChannelTypeDirectTcpIp{}    -> SshChannelTypeTagDirectTcpIp


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
  SshMsgTagUserAuthPkOk            -> 60
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
       SshMsgIgnore bytes               -> putString bytes
       SshMsgUnimplemented sn           -> putWord32be sn
       SshMsgDebug d m l                -> putDebug d m l
       SshMsgServiceRequest svc         -> putSshService svc
       SshMsgServiceAccept svc          -> putSshService svc

       SshMsgKexInit proposal           -> putSshProposal proposal
       SshMsgNewKeys                    -> return ()
       SshMsgKexDhInit n                -> putString n
       SshMsgKexDhReply c f s           -> putDhReply c f s

       SshMsgUserAuthRequest user svc m -> putUserAuthRequest user svc m
       SshMsgUserAuthFailure ms p       -> putUserAuthFailure ms p
       SshMsgUserAuthSuccess            -> return ()
       SshMsgUserAuthBanner txt lang    -> putString txt >> putString lang
       SshMsgUserAuthPkOk alg key       -> putUserAuthPkOk alg key
       SshMsgGlobalRequest name reply bytes -> putString name >> putBoolean reply >> putByteString bytes
                                                                                -- response specific data
       SshMsgRequestSuccess bytes       -> putByteString bytes -- response specific data
       SshMsgRequestFailure             -> return ()
       SshMsgChannelOpen tp id' win pkt -> putChannelOpen tp id' win pkt
       SshMsgChannelOpenConfirmation chan1 chan2 win maxPack -> putWord32be chan1 >> putWord32be chan2 >>
                                                                putWord32be win   >> putWord32be maxPack
       SshMsgChannelOpenFailure c r d l -> putWord32be c >> putWord32be (openFailureToCode r) >>
                                           putString d   >> putString l
       SshMsgChannelWindowAdjust chan adj -> putWord32be chan >> putWord32be adj
       SshMsgChannelData chan bytes     -> putWord32be chan >> putString bytes
       SshMsgChannelExtendedData chan code bytes -> putWord32be chan >> putWord32be code >> putString bytes
       SshMsgChannelEof chan            -> putWord32be chan
       SshMsgChannelClose chan          -> putWord32be chan
       SshMsgChannelRequest req id' rep -> putChannelRequest req id' rep
       SshMsgChannelSuccess chan        -> putWord32be chan
       SshMsgChannelFailure chan        -> putWord32be chan


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

putSshProposal :: Putter SshProposal
putSshProposal SshProposal{ .. } =
  do putSshCookie sshProposalCookie
     putNameList sshKexAlgs
     putNameList sshServerHostKeyAlgs
     putSshAlgs sshEncAlgs
     putSshAlgs sshMacAlgs
     putSshAlgs sshCompAlgs
     putSshAlgs sshLanguages
     putBoolean sshFirstKexFollows

     -- RESERVED
     putWord32be 0

-- TODO(conathan): make @putString . runPut@ part of the definition
-- here, instead of duplicating it everywhere, and confusing me when I
-- forget to add it. And similar for 'putSshSig'.
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

putSshPubCert (SshPubEcDsaP256 str) =
  do putString "ecdsa-sha2-nistp256"
     putString "nistp256"
     putString str

putSshPubCert (SshPubEcDsaP384 str) =
  do putString "ecdsa-sha2-nistp384"
     putString "nistp384"
     putString str

putSshPubCert (SshPubEcDsaP521 str) =
  do putString "ecdsa-sha2-nistp521"
     putString "nistp521"
     putString str

putSshPubCert (SshPubEd25519 str) =
  do putString "ssh-ed25519"
     putString str

putSshPubCert (SshPubOther name bytes) =
  do putString name
     putByteString bytes


putSshSig :: Putter SshSig

putSshSig (SshSigDss r s) =
  do putString "ssh-dss"
     putWord32be 40
     putUnsigned 20 r
     putUnsigned 20 s

putSshSig (SshSigRsa s) =
  do putString "ssh-rsa"
     putString s

putSshSig (SshSigEcDsaP256 s) =
  do putString "ecdsa-sha2-nistp256"
     putString s

putSshSig (SshSigEcDsaP384 s) =
  do putString "ecdsa-sha2-nistp384"
     putString s

putSshSig (SshSigEcDsaP521 s) =
  do putString "ecdsa-sha2-nistp521"
     putString s

putSshSig (SshSigEd25519 s) =
  do putString "ssh-ed25519"
     putString s

putSshSig (SshSigOther name bytes) =
  do putString name
     putByteString bytes

putDhReply :: SshPubCert -> S.ByteString -> SshSig -> Put
putDhReply cert f sig =
  do putString (runPut (putSshPubCert cert))
     putString f
     putString (runPut (putSshSig sig))

getDhReply :: Get SshMsg
getDhReply =
  do certLen <- getWord32be
     cert    <- isolate (fromIntegral certLen) (label "dhreply.cert" getSshPubCert)
     pub     <- label "dhreply.pub" getString
     sigLen  <- getWord32be
     sig     <- isolate (fromIntegral sigLen) (label "dhreply.sig" getSshSig)
     return (SshMsgKexDhReply cert pub sig)

putSshDiscReason :: Putter SshDiscReason
putSshDiscReason r = putWord32be $! case r of
  SshDiscNoReason                    -> 0
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

putUserAuthRequest :: S.ByteString -> SshService -> SshAuthMethod -> Put
putUserAuthRequest user service method =
  do putString user
     putSshService service
     putAuthMethod method

putAuthMethod :: Putter SshAuthMethod
putAuthMethod (SshAuthPublicKey pubKeyAlg pubKey maybeSig) =
  do putString "publickey"
     putBoolean (isJust maybeSig)
     putString pubKeyAlg
     putString (runPut (putSshPubCert pubKey))
     when (isJust maybeSig) $
       putString (runPut (putSshSig (fromJust maybeSig)))
putAuthMethod (SshAuthPassword oldPw maybeNewPw) =
  do putString "password"
     putBoolean (isJust maybeNewPw)
     putString oldPw
     when (isJust maybeNewPw) $
       putString (fromJust maybeNewPw)
putAuthMethod (SshAuthHostBased {}) = fail "putAuthMethod: unimplemented"
putAuthMethod (SshAuthNone {})      = putString "none"

putUserAuthFailure :: [ShortByteString] -> Bool -> Put
putUserAuthFailure methods partialSuccess =
  do putNameList methods
     putBoolean partialSuccess

putUserAuthPkOk :: S.ByteString -> SshPubCert -> Put
putUserAuthPkOk alg key =
  do putString alg
     putString (runPut (putSshPubCert key))

putSessionId :: Putter SshSessionId
putSessionId (SshSessionId sessionId) = putString sessionId

putChannelOpen :: SshChannelType -> Word32 -> Word32 -> Word32 -> Put
putChannelOpen tp id_us windowSize maxPacket = do
  putSshChannelType tp
  putWord32be id_us
  putWord32be windowSize
  putWord32be maxPacket

putSshChannelType :: Putter SshChannelType
putSshChannelType tp = do
  putSshChannelTypeTag $ sshChannelTypeTag tp
  case tp of
    SshChannelTypeSession -> return ()
    SshChannelTypeX11 address port -> do
      putString address
      putWord32be port
    SshChannelTypeForwardedTcpIp address1 port1 address2 port2 -> do
      putString address1
      putWord32be port1
      putString address2
      putWord32be port2
    SshChannelTypeDirectTcpIp address1 port1 address2 port2 -> do
      putString address1
      putWord32be port1
      putString address2
      putWord32be port2

putSshChannelTypeTag :: Putter SshChannelTypeTag
putSshChannelTypeTag tag = putString $ case tag of
  SshChannelTypeTagSession        -> "session"
  SshChannelTypeTagX11            -> "x11"
  SshChannelTypeTagForwardedTcpIp -> "forwarded-tcpip"
  SshChannelTypeTagDirectTcpIp    -> "direct-tcpip"

putChannelRequest :: SshChannelRequest -> Word32 -> Bool -> Put
putChannelRequest request channelId_them wantReply = do
  putWord32be channelId_them
  putChannelRequestTag $ sshChannelRequestTag request
  putBoolean wantReply
  case request of
    SshChannelRequestPtyReq term winsize modes -> do
      putString term
      putWindowSize winsize
      putString modes
    SshChannelRequestEnv name value -> do
      putString name
      putString value
    SshChannelRequestShell -> return ()
    SshChannelRequestExec cmd ->
      putString cmd
    SshChannelRequestSubsystem subsystem ->
      putString subsystem
    SshChannelRequestWindowChange winsize ->
      putWindowSize winsize

putWindowSize :: Putter SshWindowSize
putWindowSize (SshWindowSize c r x y) = do
  putWord32be c
  putWord32be r
  putWord32be x
  putWord32be y

putChannelRequestTag :: Putter SshChannelRequestTag
putChannelRequestTag tag = putString $ case tag of
  SshChannelRequestTagPtyReq       -> "pty-req"
  SshChannelRequestTagX11Req       -> "x11-req"
  SshChannelRequestTagEnv          -> "env"
  SshChannelRequestTagShell        -> "shell"
  SshChannelRequestTagExec         -> "exec"
  SshChannelRequestTagSubsystem    -> "subsystem"
  SshChannelRequestTagWindowChange -> "window-change"
  SshChannelRequestTagXonXoff      -> "xon-xoff"
  SshChannelRequestTagSignal       -> "signal"
  SshChannelRequestTagExitStatus   -> "exit-status"
  SshChannelRequestTagExitSignal   -> "exit-signal"

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
       60  -> return SshMsgTagUserAuthPkOk
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
     label (show tag) $ case tag of
       SshMsgTagDisconnect              -> getSshDisconnect
       SshMsgTagIgnore                  -> SshMsgIgnore <$> getString
       SshMsgTagUnimplemented           -> SshMsgUnimplemented <$> getWord32be
       SshMsgTagDebug                   -> getDebug
       SshMsgTagServiceRequest          -> SshMsgServiceRequest <$> getSshService
       SshMsgTagServiceAccept           -> SshMsgServiceAccept  <$> getSshService
       SshMsgTagKexInit                 -> SshMsgKexInit <$> getSshProposal
       SshMsgTagNewKeys                 -> return SshMsgNewKeys
       SshMsgTagKexDhInit               -> SshMsgKexDhInit  <$> getString
       SshMsgTagKexDhReply              -> getDhReply
       SshMsgTagUserAuthRequest         -> getAuthRequest
       SshMsgTagUserAuthFailure         -> getUserAuthFailure
       SshMsgTagUserAuthSuccess         -> return SshMsgUserAuthSuccess
       SshMsgTagUserAuthBanner          -> SshMsgUserAuthBanner <$> getString <*> getString
       SshMsgTagUserAuthPkOk            -> getUserAuthPkOk
       SshMsgTagGlobalRequest           -> SshMsgGlobalRequest <$> getString <*> getBoolean <*> getRemaining
       SshMsgTagRequestSuccess          -> SshMsgRequestSuccess <$> getRemaining
       SshMsgTagRequestFailure          -> return SshMsgRequestFailure
       SshMsgTagChannelOpen             -> getChannelOpen
       SshMsgTagChannelOpenConfirmation -> SshMsgChannelOpenConfirmation
                                                <$> getWord32be <*> getWord32be
                                                <*> getWord32be <*> getWord32be
       SshMsgTagChannelOpenFailure      -> SshMsgChannelOpenFailure
                                                <$> getWord32be <*> getOpenFailure
                                                <*> getString   <*> getString
       SshMsgTagChannelWindowAdjust     -> SshMsgChannelWindowAdjust
                                                <$> getWord32be <*> getWord32be
       SshMsgTagChannelData             -> SshMsgChannelData <$> getWord32be <*> getString
       SshMsgTagChannelExtendedData     -> SshMsgChannelExtendedData <$> getWord32be <*> getWord32be <*> getString
       SshMsgTagChannelEof              -> SshMsgChannelEof <$> getWord32be
       SshMsgTagChannelClose            -> SshMsgChannelClose <$> getWord32be
       SshMsgTagChannelRequest          -> getChannelRequest
       SshMsgTagChannelSuccess          -> SshMsgChannelSuccess <$> getWord32be
       SshMsgTagChannelFailure          -> SshMsgChannelFailure <$> getWord32be

getSshDiscReason :: Get SshDiscReason
getSshDiscReason  = label "SshDiscReason" $
  do tag <- getWord32be
     case tag of
       0  -> return SshDiscNoReason
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

getSshProposal :: Get SshProposal
getSshProposal  = label "SshProposal" $
  do sshProposalCookie    <- label "sshCookie"            getSshCookie
     sshKexAlgs           <- label "sshKexAlgs"           getNameList
     sshServerHostKeyAlgs <- label "sshServerHostKeyAlgs" getNameList
     sshEncAlgs           <- label "sshEncAlgs"           getSshAlgs
     sshMacAlgs           <- label "sshMacAlgs"           getSshAlgs
     sshCompAlgs          <- label "sshCompAlgs"          getSshAlgs
     sshLanguages         <- label "sshLanguages"         getSshAlgs
     sshFirstKexFollows   <- label "sshFirstKexFollows"   getBoolean

     -- RESERVED
     0 <- getWord32be

     return SshProposal{ .. }

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

       "ecdsa-sha2-nistp256" ->
         do "nistp256" <- getString
            str <- getString
            return (SshPubEcDsaP256 str)

       "ecdsa-sha2-nistp384" ->
         do "nistp384" <- getString
            str <- getString
            return (SshPubEcDsaP384 str)

       "ecdsa-sha2-nistp521" ->
         do "nistp521" <- getString
            str <- getString
            return (SshPubEcDsaP521 str)

       "ssh-ed25519" ->
         do str <- getString
            return (SshPubEd25519 str)

       _ ->
         do bytes <- getBytes =<< remaining
            return (SshPubOther name bytes)

getSshSig :: Get SshSig
getSshSig  = label "SshSig" $
  do name <- getString
     case name of
       "ssh-dss" ->
         do 40 <- getWord32be
            r <- getUnsigned (160 `div` 8)
            s <- getUnsigned (160 `div` 8)
            return (SshSigDss r s)

       "ssh-rsa" ->
         do s <- getString
            return (SshSigRsa s)

       "ecdsa-sha2-nistp256" ->
         do s <- getString
            return (SshSigEcDsaP256 s)

       "ecdsa-sha2-nistp384" ->
         do s <- getString
            return (SshSigEcDsaP384 s)

       "ecdsa-sha2-nistp521" ->
         do s <- getString
            return (SshSigEcDsaP521 s)

       "ssh-ed25519" ->
         do s <- getString
            return (SshSigEd25519 s)

       _ ->
         do bytes <- getBytes =<< remaining
            return (SshSigOther name bytes)

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
         do hasSignature <- getBoolean
            pubKeyAlg    <- getString
            pubKeyLen    <- getWord32be
            pubKey       <- isolate (fromIntegral pubKeyLen) getSshPubCert
            sig          <- if hasSignature
                            then do sigLen    <- getWord32be
                                    sig       <- isolate (fromIntegral sigLen)
                                                         getSshSig
                                    return (Just sig)
                            else return Nothing
            return (SshAuthPublicKey pubKeyAlg pubKey sig)

       "password" ->
         do hasNewPassword <- getBoolean
            oldPassword    <- getString
            newPassword    <- if hasNewPassword
                              then fmap Just getString
                              else return Nothing
            return (SshAuthPassword oldPassword newPassword)

       "hostbased" ->
         do hostKeyAlg <- getString
            hostKey    <- getString
            hostname   <- getString
            username   <- getString
            signature  <- getString
            return
              (SshAuthHostBased hostKeyAlg hostKey hostname username signature)

       "none" ->
            return SshAuthNone

       _ ->
            fail ("Unknown auth method: " ++ S.unpack tag)

getUserAuthFailure :: Get SshMsg
getUserAuthFailure =
  do methods        <- getNameList
     partialSuccess <- getBoolean
     return (SshMsgUserAuthFailure methods partialSuccess)

getUserAuthPkOk :: Get SshMsg
getUserAuthPkOk =
  do keyAlg  <- getString
     keyLen  <- getWord32be
     key     <- isolate (fromIntegral keyLen) getSshPubCert
     return (SshMsgUserAuthPkOk keyAlg key)

getSessionId :: Get SshSessionId
getSessionId = fmap SshSessionId getString

getChannelOpen :: Get SshMsg
getChannelOpen =
  do channelTypeTag    <- getChannelTypeTag
     senderChannel     <- getWord32be
     initialWindowSize <- getWord32be
     maximumPacketSize <- getWord32be
     ty <- case channelTypeTag of
             SshChannelTypeTagSession ->
                return SshChannelTypeSession
             SshChannelTypeTagX11     ->
                do address <- getString
                   port    <- getWord32be
                   return (SshChannelTypeX11 address port)
             SshChannelTypeTagForwardedTcpIp ->
                do address1 <- getString
                   port1    <- getWord32be
                   address2 <- getString
                   port2    <- getWord32be
                   return (SshChannelTypeForwardedTcpIp address1 port1 address2 port2)
             SshChannelTypeTagDirectTcpIp ->
                do address1 <- getString
                   port1    <- getWord32be
                   address2 <- getString
                   port2    <- getWord32be
                   return (SshChannelTypeDirectTcpIp address1 port1 address2 port2)
     return (SshMsgChannelOpen ty senderChannel initialWindowSize maximumPacketSize)

getChannelTypeTag :: Get SshChannelTypeTag
getChannelTypeTag =
  do t <- getString
     case t of
       "session"         -> return SshChannelTypeTagSession
       "x11"             -> return SshChannelTypeTagX11
       "forwarded-tcpip" -> return SshChannelTypeTagForwardedTcpIp
       "direct-tcpip"    -> return SshChannelTypeTagDirectTcpIp
       _         -> fail ("Unknown channel type: " ++ S.unpack t)

getChannelRequestTag :: Get SshChannelRequestTag
getChannelRequestTag =
  do tag <- getString
     case tag of
       "pty-req"       -> return SshChannelRequestTagPtyReq
       "x11-req"       -> return SshChannelRequestTagX11Req
       "env"           -> return SshChannelRequestTagEnv
       "shell"         -> return SshChannelRequestTagShell
       "exec"          -> return SshChannelRequestTagExec
       "subsystem"     -> return SshChannelRequestTagSubsystem
       "window-change" -> return SshChannelRequestTagWindowChange
       "xon-xoff"      -> return SshChannelRequestTagXonXoff
       "signal"        -> return SshChannelRequestTagSignal
       "exit-status"   -> return SshChannelRequestTagExitStatus
       "exit-signal"   -> return SshChannelRequestTagExitSignal
       _               -> fail ("Unknown request tag: " ++ S.unpack tag)

getWindowSize :: Get SshWindowSize
getWindowSize =
  SshWindowSize <$> getWord32be <*> getWord32be <*> getWord32be <*> getWord32be

getChannelRequest :: Get SshMsg
getChannelRequest =
  do recipientChannel <- getWord32be
     requestTag       <- getChannelRequestTag
     wantReply        <- getBoolean
     request <- case requestTag of
       SshChannelRequestTagPtyReq ->
         SshChannelRequestPtyReq <$> getString <*> getWindowSize <*> getString
       SshChannelRequestTagEnv ->
         do name  <- getString
            value <- getString
            return (SshChannelRequestEnv name value)
       SshChannelRequestTagShell ->
            return SshChannelRequestShell
       SshChannelRequestTagExec ->
            SshChannelRequestExec <$> getString
       SshChannelRequestTagSubsystem ->
            SshChannelRequestSubsystem <$> getString
       SshChannelRequestTagWindowChange ->
            SshChannelRequestWindowChange <$> getWindowSize

       _ -> fail ("Unsupported request: " ++ show requestTag )

     return (SshMsgChannelRequest request recipientChannel wantReply)

getOpenFailure :: Get SshOpenFailure
getOpenFailure =
  do code <- getWord32be
     case codeToOpenFailure code of
       Just tag -> return tag
       Nothing  -> fail "Unknown Channel Open Failure type"

getRemaining :: Get S.ByteString
getRemaining = getBytes =<< remaining
