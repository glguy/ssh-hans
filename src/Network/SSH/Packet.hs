{-# LANGUAGE NamedFieldPuns #-}
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
import           Data.ByteArray (constEq)
import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import           Data.Monoid ((<>))
import           Data.Word
import           Data.Serialize
                     ( Get, Putter, runGet, runPut, label, remaining
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
     putString e
     putString f
     putByteString k -- raw encoding

putSshIdent :: Putter SshIdent
putSshIdent sshIdent =
  putLazyByteString $ L.fromStrict (sshIdentString sshIdent <> "\r\n")

-- | Given a way to render something, turn it into an ssh packet.
putSshPacket ::
  DRG gen => Word32 -> Cipher -> ActiveCipher -> Mac -> gen -> L.ByteString -> (L.ByteString,ActiveCipher,gen)

putSshPacket seqNum Cipher{randomizePadding,paddingSize} ActiveCipher{acCrypt} mac gen bytes =
  (L.fromChunks packetChunks, st', gen')
  where
  packetChunks
    | mETM mac  = [ lenBytes, cipherText, tag ]
    | otherwise = [           cipherText, tag ]

  lenBytes = runPut $ putWord32be $ fromIntegral
           $ 1 + bytesLen + paddingLen

  tag = computeMac mac seqNum
      $ if mETM mac
        then [lenBytes, cipherText]
        else [plainText]

  (st',cipherText) = acCrypt seqNum plainText

  plainText = runPut $
    do unless (mETM mac) (putByteString lenBytes)
       putWord8 (fromIntegral paddingLen)
       putLazyByteString bytes
       putByteString padding

  bytesLen = fromIntegral (L.length bytes)
  paddingLen = paddingSize (bytesLen + if mETM mac then 1 else 5)
  (padding, gen')
    | randomizePadding = randomBytesGenerate paddingLen gen
    | otherwise        = (S.replicate paddingLen 0, gen)

-- Parsing ---------------------------------------------------------------------

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
  Word32 -> Cipher -> ActiveCipher -> Mac -> Get (S.ByteString,ActiveCipher)
getSshPacket seqNum _ ActiveCipher{acCrypt} mac
  | mETM mac = label "SshPacket" $

  do -- figure out packet size
     packetLen <- getWord32be
     cipherText <- getBytes (fromIntegral packetLen)

     -- validate signature
     let computedSig = computeMac mac seqNum
                         [runPut (putWord32be packetLen), cipherText]
     actualSig <- getBytes (S.length computedSig)
     unless (constEq actualSig computedSig)
       (fail "signature validation failed")

     -- compute payload
     let (st', payload) = acCrypt seqNum cipherText
     case runGet removePadding payload of
       Left e -> fail e
       Right x -> return (x,st')

-- Original packet format without ETM
getSshPacket seqNum Cipher{blockSize} ActiveCipher{acLength,acCrypt} mac = label "SshPacket" $

  do -- figure out packet size
     let blockLen = max blockSize 8
     firstBlock <- lookAhead (getBytes blockLen)
     let payloadLen = acLength seqNum firstBlock

     -- compute payload
     cipherText <- getBytes (payloadLen + 4)
     let (st',payload) = acCrypt seqNum cipherText

     -- validate signature
     let computedSig = computeMac mac seqNum [payload]
     actualSig <- getBytes (S.length computedSig)
     unless (constEq computedSig actualSig)
       (fail "Signature validation failed")

     case runGet (skip 4 >> removePadding) payload of
       Left e -> fail e
       Right x -> return (x,st')

removePadding :: Get S.ByteString
removePadding =
  do padLen <- fmap fromIntegral getWord8
     n      <- remaining
     unless (4 <= padLen && padLen < n) (fail "bad padding length")
     getBytes (n - padLen)
