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
                     , putWord32be, Putter, putByteString )

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
          -> S.ByteString   -- ^ e
          -> S.ByteString   -- ^ f
          -> S.ByteString   -- ^ K
          -> S.ByteString
sshDhHash v_c v_s i_c i_s k_s e f k = runPut $
  do putString (putIdent v_c)
     putString (putIdent v_s)
     putString (runPut (putSshMsg (SshMsgKexInit i_c)))
     putString (runPut (putSshMsg (SshMsgKexInit i_s)))
     putString (runPut (putSshPubCert k_s))
     putByteString e -- encoding varies
     putByteString f -- encoding varies
     putByteString k -- encoding varies
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
putSshPacket Cipher{..} mac render = (packet,Cipher{cipherState=st',..},mac')
  where
  packet = L.fromChunks [ encBody, sig ]

  (st',encBody) = crypt cipherState body
  (sig,mac')    = sign mac body

  body = runPut $
    do putWord32be (fromIntegral packetLen)
       putWord8 (fromIntegral paddingLen)
       putByteString bytes
       putByteString padding

  bytes    = runPut render
  bytesLen = S.length bytes
  paddingLen = paddingSize bytesLen
  packetLen = 1 + bytesLen + paddingLen

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
getSshPacket Cipher{..} mac getPayload = label "SshPacket" $
  do let blockLen = max blockSize 8
     firstBlock <- lookAhead (getBytes blockLen)
     let packetLen = getLength cipherState firstBlock

     -- decrypt and decode the packet
     ((payload,sig',mac'),cipher') <- decryptGet (packetLen + 4) $
       do (sig',mac') <- lookAhead genSig

          skip 4
          paddingLen <- fmap fromIntegral getWord8

          rest <- remaining
          let payloadLen = rest - paddingLen
          payload <- label "payload" (isolate payloadLen getPayload)
          label "padding" (skip paddingLen)

          return (payload,sig',mac')

     sig <- getBytes (S.length sig')
     unless (sig == sig') (fail ("Signature validation failed: " ++ show (sig, sig')))

     return (payload, cipher', mac')

  where

  decryptGet len m =
     do encBytes <- getBytes len
        let (st',bytes) = crypt cipherState encBytes
        case runGet m bytes of
          Right a  -> return (a,Cipher{cipherState=st',..})
          Left err -> fail err

  genSig =
    do payload <- getBytes =<< remaining
       return (sign mac payload)

