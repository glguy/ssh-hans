{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.Mac (
    Mac()
  , SeqNum
  , sign
  , switch

  , mac_none
  , mac_hmac_sha1
  ) where

import qualified Data.ByteString.Char8 as S
import qualified Data.ByteString.Lazy as L
import           Data.Serialize ( runPut, putWord32be, putByteString )
import           Data.Word ( Word32 )

import qualified Crypto.MAC.HMAC as HMAC
import qualified Crypto.Hash.Algorithms as Hash
import           Data.ByteArray (convert)


type SeqNum = Word32

data Mac = Mac { mName       :: !S.ByteString
               , mNextSeqNum :: !SeqNum
               , mFunction   :: S.ByteString -> S.ByteString
               }

instance Show Mac where
  show Mac { .. } = S.unpack mName

-- | Sign a packet, yielding out a signature, and the new Mac to use.
sign :: Mac -> S.ByteString -> (S.ByteString,Mac)
sign Mac { .. } bytes = (sig, Mac { mNextSeqNum = mNextSeqNum + 1, .. })
  where
  sig = mFunction (runPut (putWord32be mNextSeqNum >> putByteString bytes))


-- | Migrate from one mac to another, in the case of a rekey.
switch :: Mac -> Mac -> Mac
switch oldMac newMac = newMac { mNextSeqNum = mNextSeqNum oldMac }


-- Algorithms ------------------------------------------------------------------

mac_none :: Mac
mac_none  =
  Mac { mName       = "none"
      , mNextSeqNum = 0
      , mFunction   = const S.empty
      }

mac_hmac_sha1 :: L.ByteString -> Mac
mac_hmac_sha1 keyBytes =
  Mac { mName       = "hmac-sha1"
      , mNextSeqNum = 0
      , mFunction   = convert . mac
      }
  where
  mac :: S.ByteString -> HMAC.HMAC Hash.SHA1
  mac = HMAC.hmac (L.toStrict (L.take 20 keyBytes))
