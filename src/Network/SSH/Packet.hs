{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.Packet where

import Network.SSH.Ciphers
import Network.SSH.Mac
import Network.SSH.Messages
import Network.SSH.Protocol

import           Control.Monad ( unless, guard, msum )
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import           Data.Char ( chr )
import           Data.Serialize
                     ( Get, Put, runGet, runPut, label, isolate, remaining
                     , lookAhead, skip, getBytes, getWord8, putWord8
                     , getWord32be, putWord32be, Putter, putByteString )
import           Data.Word ( Word32 )

data SshIdent = SshIdent { sshProtoVersion
                         , sshSoftwareVersion
                         , sshComments        :: !S.ByteString
                         } deriving (Show,Eq)

-- Hash Generation -------------------------------------------------------------

sshDhHash :: SshIdent       -- ^ V_C
          -> SshIdent       -- ^ V_S
          -> SshKex         -- ^ I_C
          -> SshKex         -- ^ I_S
          -> SshPubCert     -- ^ K_S
          -> Integer        -- ^ e
          -> Integer        -- ^ f
          -> Integer        -- ^ K
          -> S.ByteString
sshDhHash v_c v_s i_c i_s k_s e f k = runPut $
  do putString (putIdent v_c)
     putString (putIdent v_s)
     putString (runPut (putSshMsg (SshMsgKexInit i_c)))
     putString (runPut (putSshMsg (SshMsgKexInit i_s)))
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

-- | Given a way to render something, turn it into an ssh packet.
putSshPacket :: Cipher -> Mac -> Put -> (L.ByteString,Cipher,Mac)
putSshPacket cipher mac render = (packet,cipher',mac')
  where
  packet = L.fromChunks [ encBody, sig ]

  (encBody,cipher') = encrypt cipher body
  (sig,mac')        = sign mac body

  body = runPut $
    do putWord32be (fromIntegral (1 + bytesLen + paddingLen))
       putWord8 (fromIntegral paddingLen)
       putByteString bytes
       putByteString padding

  bytes    = runPut render
  bytesLen = S.length bytes

  align = max (blockSize cipher) 8

  bytesRem   = (4 + 1 + bytesLen) `mod` align

  -- number of bytes needed to align on block size
  alignBytes | bytesRem == 0 = 0
             | otherwise     = align - bytesRem

  paddingLen | alignBytes == 0 =              align
             | alignBytes <  4 = alignBytes + align
             | otherwise       = alignBytes

  -- XXX the padding SHOULD be random bytes, so this should probably change
  padding = S.replicate paddingLen 0x0


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

-- | Given a way to parse the payload of an ssh packet, do the required
-- book-keeping surrounding the data.
getSshPacket :: Show a =>  Cipher -> Mac -> Get a -> Get (a,Cipher,Mac)
getSshPacket cipher mac getPayload = label "SshPacket" $
  do let blockLen = max (blockSize cipher) 8
     ((packetLen,paddingLen),_) <- lookAhead $ decryptGet blockLen $
       do packetLen  <- getWord32be
          paddingLen <- getWord8

          unless (paddingLen >= 4) (fail "Corrupted padding length")

          return (fromIntegral packetLen, fromIntegral paddingLen)

     -- decrypt and decode the packet
     ((payload,sig',mac'),cipher') <- decryptGet (packetLen + 4) $
       do (sig',mac') <- lookAhead (genSig (packetLen + 4))

          skip 5 -- skip the packet len and payload len, parsed above already

          let payloadLen = packetLen - paddingLen - 1
          payload <- label "payload" (isolate payloadLen getPayload)
          label "padding" (skip paddingLen)

          return (payload,sig',mac')

     sig <- getBytes (S.length sig')
     unless (sig == sig') (fail ("Signature validation failed: " ++ show (sig, sig')))

     return (payload, cipher', mac')

  where

  decryptGet len m =
    do encBytes <- getBytes len
       let (bytes,cipher') = decrypt cipher encBytes
       case runGet m bytes of
         Right a  -> return (a,cipher')
         Left err -> fail err

  genSig payloadLen =
    do payload <- getBytes payloadLen
       return (sign mac payload)

