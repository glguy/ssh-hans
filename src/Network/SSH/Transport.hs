{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.Transport where

import           Control.Monad ( guard, msum, unless )
import           Data.Bits ( shiftR, shiftL, (.&.), testBit )
import qualified Data.ByteString as S
import           Data.Char ( chr, ord )
import           Data.List ( intersperse, genericLength )
import           Data.Serialize
                     ( Get, Putter, getWord8, putWord8, putByteString, label
                     , putWord32be, getWord32be, isolate, getBytes, remaining
                     , lookAhead, skip, runPut )
import           Data.Word ( Word8, Word32 )

import Debug.Trace


data SshIdent = SshIdent { sshProtoVersion
                         , sshSoftwareVersion
                         , sshComments        :: !S.ByteString
                         } deriving (Show,Eq)

-- | Always 16 bytes of random data.
newtype SshCookie = SshCookie S.ByteString
                    deriving (Show,Eq)

newtype SshSessionId = SshSessionId S.ByteString

data SshAlgs = SshAlgs { sshClientToServer :: [S.ByteString]
                       , sshServerToClient :: [S.ByteString]
                       } deriving (Show,Eq)


ssh_MSG_KEXINIT :: Word8
ssh_MSG_KEXINIT  = 20

data SshKeyExchange = SshKeyExchange { sshCookie            :: !SshCookie
                                     , sshKexAlgs           :: [S.ByteString]
                                     , sshServerHostKeyAlgs :: [S.ByteString]
                                     , sshEncAlgs           :: !SshAlgs
                                     , sshMacAlgs           :: !SshAlgs
                                     , sshCompAlgs          :: !SshAlgs
                                     , sshLanguages         :: !SshAlgs
                                     , sshFirstKexFollows   :: Bool
                                     } deriving (Show,Eq)


ssh_MSG_NEWKEYS :: Word8
ssh_MSG_NEWKEYS  = 21

data SshNewKeys = SshNewKeys
                  deriving (Show,Eq)

data SshPubCert = SshPubDss !Integer !Integer !Integer !Integer
                | SshPubRsa !Integer !Integer
                | SshPubOther !S.ByteString !S.ByteString
                  deriving (Show,Eq)

data SshSig = SshSigDss !Integer !Integer
            | SshSigRsa !S.ByteString
            | SshSigOther S.ByteString S.ByteString
              deriving (Show,Eq)

sshPubCertName :: SshPubCert -> S.ByteString
sshPubCertName SshPubDss {}      = "ssh-dss"
sshPubCertName SshPubRsa {}      = "ssh-rsa"
sshPubCertName (SshPubOther n _) = n

ssh_MSG_KEXDH_INIT :: Word8
ssh_MSG_KEXDH_INIT  = 30

data SshKexDhInit = SshKexDhInit { sshE :: !Integer
                                 } deriving (Show,Eq)

ssh_MSG_KEXDH_REPLY :: Word8
ssh_MSG_KEXDH_REPLY  = 31

data SshKexDhReply = SshKexDhReply { sshHostPubKey :: SshPubCert
                                   , sshF          :: !Integer
                                   , sshHostSig    :: SshSig
                                   } deriving (Show,Eq)


-- Hash Generation -------------------------------------------------------------

sshDhHash :: SshIdent       -- ^ V_C
          -> SshIdent       -- ^ V_S
          -> SshKeyExchange -- ^ I_C
          -> SshKeyExchange -- ^ I_S
          -> SshPubCert     -- ^ K_S
          -> Integer        -- ^ e
          -> Integer        -- ^ f
          -> Integer        -- ^ K
          -> S.ByteString
sshDhHash v_c v_s i_c i_s k_s e f k = runPut $
  do putString (putIdent v_c)
     putString (putIdent v_s)
     putString (runPut (putSshKeyExchange i_c))
     putString (runPut (putSshKeyExchange i_s))
     putString (runPut (putSshPubCert k_s))
     putMpInt e
     putMpInt f
     putMpInt k
  where
  -- special version of putSshIdent that drops the CR-LF at the end
  putIdent v = let bytes = runPut (putSshIdent v)
                in S.take (S.length bytes - 2) bytes


-- Rendering -------------------------------------------------------------------

putSshIdent :: Putter SshIdent
putSshIdent SshIdent { .. } =
  do putByteString "SSH-"
     putByteString sshProtoVersion
     putByteString "-"
     putByteString sshSoftwareVersion
     unless (S.null sshComments) $
       do putByteString " "
          putByteString sshComments
     putByteString "\r\n"

putSshCookie :: Putter SshCookie
putSshCookie (SshCookie bytes) =
     putByteString bytes

putNameList :: Putter [S.ByteString]
putNameList names =
  do let len | null names = 0
             | otherwise  = sum (map S.length names)
                          + length names - 1 -- commas
     putWord32be (fromIntegral len)
     mapM_ putByteString (intersperse "," names)

putSshAlgs :: Putter SshAlgs
putSshAlgs SshAlgs { .. } =
  do putNameList sshClientToServer
     putNameList sshServerToClient

-- | Given a way to render something, turn it into an ssh packet.
--
-- XXX this needs to take into account the block algorithm, and potential mac.
putSshPacket :: Maybe Int -> Putter a -> Putter a
putSshPacket mbCbSize render a =
  do putWord32be (fromIntegral (1 + bytesLen + paddingLen))
     putWord8 (fromIntegral paddingLen)
     putByteString bytes
     putByteString padding
  where
  bytes    = runPut (render a)
  bytesLen = S.length bytes

  align = case mbCbSize of
            Just cbSize -> max cbSize 8
            otherwise   -> 8

  bytesRem   = (4 + 1 + bytesLen) `mod` align

  -- number of bytes needed to align on block size
  alignBytes | bytesRem == 0 = 0
             | otherwise     = align - bytesRem

  paddingLen | alignBytes == 0 =              align
             | alignBytes <  4 = alignBytes + align
             | otherwise       = alignBytes

  -- XXX the padding SHOULD be random bytes, so this should probably change
  padding = S.replicate paddingLen 0x0

putSshKeyExchange :: Putter SshKeyExchange
putSshKeyExchange SshKeyExchange { .. } =
  do putWord8 ssh_MSG_KEXINIT
     putSshCookie sshCookie
     putNameList sshKexAlgs
     putNameList sshServerHostKeyAlgs
     putSshAlgs sshEncAlgs
     putSshAlgs sshMacAlgs
     putSshAlgs sshCompAlgs
     putSshAlgs sshLanguages
     putWord8 $ if sshFirstKexFollows
                   then 1
                   else 0
     -- RESERVED
     putWord32be 0


putMpInt :: Putter Integer
putMpInt i =
  do putWord32be len
     mapM_ putWord8 bytes
  where
  (len,bytes) = unpack i

unpack :: Integer -> (Word32, [Word8])
unpack  = go 0 []
  where
  go len bytes n
    | abs n < 0xff = finalize len bytes n
    | otherwise    = let byte = fromInteger (n .&. 0xff)
                         n'   = n `shiftR` 8
                         len' = len + 1
                      in go len' (byte : bytes) (byte `seq` len' `seq` n')

  finalize len bytes n
    | n == 0               = (len,                     bytes)
    | n > 0 && testBit n 7 = (len + 2, 0 : fromInteger n : bytes)
    | otherwise            = (len + 1,     fromInteger n : bytes)

putUnsigned :: Int -> Putter Integer
putUnsigned size val =
  do let (padding,bytes) = go [] val
     mapM_ putWord8 padding
     mapM_ putWord8 bytes
  where

  go acc n
    | n <= 0xff = let res    = reverse (fromInteger n : acc)
                      len    = length res
                      padLen = size - len
                   in (replicate padLen 0, res)

    | otherwise = let acc' = fromInteger (n .&. 0xff) : acc
                   in go acc' (acc' `seq` (n `shiftR` 8))


putString :: Putter S.ByteString
putString bytes =
  do putWord32be (fromIntegral (S.length bytes))
     putByteString bytes

putSshKexDhInit :: Putter SshKexDhInit
putSshKexDhInit SshKexDhInit { .. } =
  do putWord8 ssh_MSG_KEXDH_INIT
     putMpInt sshE

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


putSshKexDhReply :: Putter SshKexDhReply
putSshKexDhReply SshKexDhReply { .. } =
  do putWord8 ssh_MSG_KEXDH_REPLY
     putString (runPut (putSshPubCert sshHostPubKey))
     putMpInt sshF
     putString (runPut (putSshSig sshHostSig))


putSshNewKeys :: Putter SshNewKeys
putSshNewKeys _ =
     putWord8 ssh_MSG_NEWKEYS


-- Parsing ---------------------------------------------------------------------

getCrLf :: Get ()
getCrLf  =
  do cr <- getWord8
     guard (cr == 13)

     left <- remaining
     if left > 0
        then do lf <- getWord8
                guard (lf == 10)
        else return ()

getCh :: Char -> Get ()
getCh c =
  do c' <- getWord8
     guard (c == chr (fromIntegral c'))

getBytesUntil :: Get () -> Get S.ByteString
getBytesUntil end =
  do start      <- remaining
     (off,stop) <- lookAhead (go 0)
     guard (off > 0)
     bytes      <- getBytes off
     -- skip the length of the ending action
     skip (start - (stop + off))
     return bytes
  where
  go off = msum [ do end
                     stop <- remaining
                     return (off, stop)
                , do _ <- getWord8
                     go $! off + 1
                ]

getSshIdent :: Get SshIdent
getSshIdent  = label "SshIdent" $
  do "SSH"              <- getBytesUntil (getCh '-')
     sshProtoVersion    <- getBytesUntil (getCh '-')

     msum [ do sshSoftwareVersion <- getBytesUntil (getCh ' ')
               sshComments        <- getBytesUntil  getCrLf
               return SshIdent { .. }
          , do sshSoftwareVersion <- getBytesUntil  getCrLf
               let sshComments = ""
               return SshIdent { .. }
          ]

getSshCookie :: Get SshCookie
getSshCookie  = SshCookie `fmap` getBytes 16

getNameList :: Get [S.ByteString]
getNameList  =
  do len   <- getWord32be
     bytes <- getBytes (fromIntegral len)
     return (S.splitWith (== comma) bytes)
  where
  comma = fromIntegral (ord ',')

getSshAlgs :: Get SshAlgs
getSshAlgs  =
  do sshClientToServer <- getNameList
     sshServerToClient <- getNameList
     return SshAlgs { .. }

-- | Given a way to parse the payload of an ssh packet, do the required
-- book-keeping surrounding the data.
getSshPacket :: Maybe Int -> Get a -> Get (a,S.ByteString)
getSshPacket mbCbSize getPayload =
  do -- XXX verify that packetLen is reasonable.  The rfc requires that
     -- it be able to handle at least 35000.
     packetLen  <- getWord32be
     paddingLen <- getWord8

     unless (paddingLen >= 4) (fail "Corrupted padding length")

     let payloadLen = fromIntegral packetLen - fromIntegral paddingLen - 1
     payload <- isolate payloadLen getPayload

     skip (fromIntegral paddingLen)

     mac <- getBytes =<< remaining

     return (payload, mac)

getSshKeyExchange :: Get SshKeyExchange
getSshKeyExchange  = label "SshKeyExchange" $
  do tag <- getWord8
     guard (tag == ssh_MSG_KEXINIT)

     sshCookie            <- label "sshCookie"            getSshCookie
     sshKexAlgs           <- label "sshKexAlgs"           getNameList
     sshServerHostKeyAlgs <- label "sshServerHostKeyAlgs" getNameList
     sshEncAlgs           <- label "sshEncAlgs"           getSshAlgs
     sshMacAlgs           <- label "sshMacAlgs"           getSshAlgs
     sshCompAlgs          <- label "sshCompAlgs"          getSshAlgs
     sshLanguages         <- label "sshLanguages"         getSshAlgs
     byte                 <- label "sshFirstKexFollows"   getWord8
     let sshFirstKexFollows | byte == 0 = False
                            | otherwise = True

     -- RESERVED
     _ <- getWord32be

     return SshKeyExchange { .. }

getUnsigned :: Int -> Get Integer
getUnsigned  = go []
  where
  go acc 0 = return $! foldr step 0 acc
  go acc n = do w <- getWord8
                let acc' = w : acc
                go acc' (acc' `seq` n - 1)

  step w acc = acc `shiftL` 8 + toInteger w

getMpInt :: Get Integer
getMpInt  =
  do numBytes <- getWord32be

     if numBytes == 0
        then return 0
        else isolate (fromIntegral numBytes) $
               do w <- getWord8
                  let msb | w == 0      = 0
                          | testBit w 7 = toInteger w - 0x100
                          | otherwise   = toInteger w

                  go msb (numBytes - 1)
  where
  go acc 0 =    return acc
  go acc n = do w <- getWord8
                let acc' = (acc `shiftL` 8) + fromIntegral w
                go acc' (acc' `seq` n-1)

getString :: Get S.ByteString
getString  =
  do len <- getWord32be
     getBytes (fromIntegral len)

getSshKexDhInit :: Get SshKexDhInit
getSshKexDhInit  = label "SshKexDhInit" $
  do tag <- getWord8
     guard (tag == ssh_MSG_KEXDH_INIT)

     sshE <- getMpInt
     return SshKexDhInit { .. }

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


getSshKexDhReply :: Get SshKexDhReply
getSshKexDhReply  = label "SshKexDhReply" $
  do tag <- getWord8
     guard (tag == ssh_MSG_KEXDH_REPLY)

     pubKeyLen     <- getWord32be
     sshHostPubKey <- isolate (fromIntegral pubKeyLen) getSshPubCert

     sshF          <- getMpInt

     sigLen        <- getWord32be
     sshHostSig    <- isolate (fromIntegral sigLen) getSshSig

     return SshKexDhReply { .. }


getSshNewKeys :: Get SshNewKeys
getSshNewKeys  =
  do tag <- getWord8
     guard (tag == ssh_MSG_NEWKEYS)

     return SshNewKeys
