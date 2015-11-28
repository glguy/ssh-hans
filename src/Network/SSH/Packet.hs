{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE RecordWildCards #-}

module Network.SSH.Packet where

import Network.SSH.Ciphers
import Network.SSH.Mac
import Network.SSH.Messages
import Network.SSH.Protocol

import           Control.Applicative ((<|>))
import           Control.Monad (unless, guard)
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import           Data.Char ( chr )
import           Data.Word
import           Data.Monoid ((<>))
import           Data.Serialize
                     ( Get, runGet, runPut, label, remaining
                     , lookAhead, skip, getBytes, getWord8, putWord8
                     , getWord32be, putWord32be, putByteString
                     , putLazyByteString )

import           Crypto.Random

newtype SshIdent = SshIdent { sshIdentString :: S.ByteString }
  deriving (Show,Read,Eq)

-- Hash Generation -------------------------------------------------------------

sshDhHash :: SshIdent       -- ^ V_C
          -> SshIdent       -- ^ V_S
          -> SshProposal    -- ^ I_C
          -> SshProposal    -- ^ I_S
          -> SshPubCert     -- ^ K_S
          -> S.ByteString   -- ^ e
          -> S.ByteString   -- ^ f
          -> S.ByteString   -- ^ K
          -> S.ByteString
sshDhHash v_c v_s i_c i_s k_s e f k = runPut $
  do putString (sshIdentString v_c)
     putString (sshIdentString v_s)
     putString (runPut (putSshMsg (SshMsgKexInit i_c)))
     putString (runPut (putSshMsg (SshMsgKexInit i_s)))
     putString (runPut (putSshPubCert k_s))
     putByteString e -- encoding varies
     putByteString f -- encoding varies
     putByteString k -- encoding varies


-- | Given a way to render something, turn it into an ssh packet.
putSshPacket ::
  DRG gen => Word32 -> Cipher -> Mac -> gen -> L.ByteString -> (L.ByteString,Cipher,gen)

putSshPacket seqNum Cipher{..} mac gen bytes
  | mETM mac = (packet,Cipher{cipherState=st',..},gen')
  where
  packet = L.fromChunks [ lenBytes, encBody, sig ]

  (st',encBody) = encrypt seqNum cipherState body
  sig           = sign seqNum mac (lenBytes <> encBody)

  lenBytes = runPut (putWord32be (fromIntegral payloadLen))

  body = runPut $
    do putWord8 (fromIntegral paddingLen)
       putLazyByteString bytes
       putByteString padding

  bytesLen = fromIntegral (L.length bytes)
  paddingLen = paddingSize bytesLen
  payloadLen = 1 + bytesLen + paddingLen
  (padding, gen')
    | randomizePadding = randomBytesGenerate paddingLen gen
    | otherwise        = (S.replicate paddingLen 0, gen)

-- Original packet format (without ETM)
putSshPacket seqNum Cipher{..} mac gen bytes = (packet,Cipher{cipherState=st',..},gen')
  where
  packet = L.fromChunks [ encBody, sig ]

  (st',encBody) = encrypt seqNum cipherState body
  sig           = sign seqNum mac body

  body = runPut $
    do putWord32be (fromIntegral packetLen)
       putWord8 (fromIntegral paddingLen)
       putLazyByteString bytes
       putByteString padding

  bytesLen = fromIntegral (L.length bytes)
  paddingLen = paddingSize (4+bytesLen)
  packetLen = 1 + bytesLen + paddingLen
  (padding, gen') = randomBytesGenerate paddingLen gen

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

getOneLine :: Get S.ByteString
getOneLine =
  do n <- lookAhead (findCrLf 0)
     xs <- getBytes n
     skip 2
     return xs
  where
  findCrLf !acc = here acc <|> (skip 1 >> findCrLf (acc+1))
  here acc = do "\r\n" <- getBytes 2
                return acc

getSshIdent :: Get SshIdent
getSshIdent  = label "SshIdent" $
  do str <- getOneLine
     guard (S.isPrefixOf "SSH-2.0-" str)
     return (SshIdent str)

-- | Given a way to parse the payload of an ssh packet, do the required
-- book-keeping surrounding the data.
getSshPacket ::
  Word32 -> Cipher -> Mac -> Get (S.ByteString,Cipher)
getSshPacket seqNum Cipher{..} mac
  | mETM mac = label "SshPacket" $
  do packetLen <- getWord32be
     payload   <- getBytes (fromIntegral packetLen)
     let computedSig = sign seqNum mac (runPut (putWord32be packetLen >> putByteString payload))
     sig <- getBytes (S.length computedSig)
     unless (sig == computedSig) (fail "signature validation failed")

     let (st', bytes) = decrypt seqNum cipherState payload
     case runGet (finish (fromIntegral packetLen)) bytes of
       Left e -> fail e
       Right x -> return (x,Cipher{cipherState=st',..})

  where
  finish n =
    do padLen <- fmap fromIntegral getWord8
       unless (4 <= padLen && padLen < n) (fail "bad padding length")
       getBytes (n-padLen-1)

-- Original packet format without ETM
getSshPacket seqNum Cipher{..} mac = label "SshPacket" $
  do let blockLen = max blockSize 8
     firstBlock <- lookAhead (getBytes blockLen)
     let packetLen = getLength seqNum cipherState firstBlock

     -- decrypt and decode the packet
     ((payload,sig'),cipher') <- decryptGet (packetLen + 4) $
       do sig' <- lookAhead genSig

          skip 4
          paddingLen <- getWord8
          n          <- remaining
          payload    <- getBytes (n - fromIntegral paddingLen)
          return (payload,sig')

     sig <- getBytes (S.length sig')
     unless (sig == sig') (fail ("Signature validation failed: " ++ show (sig, sig')))

     return (payload, cipher')

  where

  decryptGet len m =
     do encBytes <- getBytes len
        let (st',bytes) = decrypt seqNum cipherState encBytes
        case runGet m bytes of
          Right a  -> return (a,Cipher{cipherState=st',..})
          Left err -> fail err

  genSig =
    do payload <- getBytes =<< remaining
       return (sign seqNum mac payload)

