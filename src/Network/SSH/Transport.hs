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

ssh_MSG_KEXDH_INIT :: Word8
ssh_MSG_KEXDH_INIT  = 30

data SshKexDhInit = SshKexDhInit { sshE :: Integer
                                 } deriving (Show,Eq)

ssh_MSG_KEXDH_REPLY :: Word8
ssh_MSG_KEXDH_REPLY  = 31


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
unpack  = go 1 []
  where
  go len bytes n
    | abs n < 0xff = finalize len bytes n
    | otherwise    = let byte = fromInteger (n .&. 0xff)
                         n'   = n `shiftR` 8
                         len' = len + 1
                      in go len' (byte : bytes) (byte `seq` len' `seq` n')

  finalize len bytes n
    | n > 0 && testBit n 7 = (len, 0 : fromInteger n : bytes)
    | otherwise            = (len,     fromInteger n : bytes)

putSshKexDhInit :: Putter SshKexDhInit
putSshKexDhInit SshKexDhInit { .. } =
  do putWord8 ssh_MSG_KEXDH_INIT
     putMpInt sshE


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


getMpInt :: Get Integer
getMpInt  =
  do numBytes <- getWord32be
     isolate (fromIntegral numBytes) $
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

getSshKexDhInit :: Get SshKexDhInit
getSshKexDhInit  = label "SshKexDhInit" $
  do tag <- getWord8
     guard (tag == ssh_MSG_KEXDH_INIT)

     sshE <- getMpInt
     return SshKexDhInit { .. }
