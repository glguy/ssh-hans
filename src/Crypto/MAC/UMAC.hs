{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE ForeignFunctionInterface #-}

-- | This module implements the UMAC message authentication code. It offers
-- two interfaces: stateful and pure. Additionally this module can compute
-- MACs of two sizes: 64 and 128 bit.
--
-- The stateful interface consists of 'new', 'update', 'final', 'reset'.
-- Construct a new context for each key. Update that context with all of
-- the bytes to be included in the MAC, and use 'final' to extract the
-- MAC. 'reset' is available to reset a context without computing a tag.
--
-- @
-- example :: IO 'S.ByteString'
-- example =
--   do u <- 'new' myKey
--      'update' u chunk1
--      'update' u chunk2
--      'final'  u myNonce
-- @
--
-- The pure interface consists of 'compute', 'compute64', and 'compute128'.
-- The first of these is polymorphic in the MAC length and the remaining
-- are specializations of the first. These functions can compute a MAC in
-- a pure context but are not able to benefit from reusing contexts across
-- multiple MACs.
--
-- This module binds to the C implementation of UMAC written by Ted Krovetz
module Crypto.MAC.UMAC
  ( UmacSize
  , USize(..)
  , UmacException(..)
  , tagSize
  , keySize
  , nonceSize

  -- * Stateful interface
  , UMAC
  , new
  , update
  , final
  , reset

  -- * Pure interface
  , compute
  , compute64
  , compute128
  ) where

import           Control.Exception
import           Control.Monad
import           Data.ByteArray as BA
import qualified Data.ByteString as S
import           Data.Foldable
import           Data.Proxy
import           Foreign.C
import           Foreign.ForeignPtr
import           Foreign.Ptr

------------------------------------------------------------------------

-- | This type is used to select MAC length
data USize
  = U64  -- ^ Select 64-bit MAC
  | U128 -- ^ Select 128-bit MAC

data UmacCtx (sz :: USize)

-- | Stateful MAC context parameterized by a type indicating MAC length.
newtype UMAC sz = UMAC (ForeignPtr (UmacCtx sz))

-- | The type of exceptions that can occur using this module
data UmacException
  = UmacBadAllocation -- ^ Raised when memory allocation fails in C
  | UmacBadKey        -- ^ Raised when given key has incorrect length
  | UmacBadNonce      -- ^ Raised when given nonce has incorrect length
  deriving (Show, Read, Eq, Ord)

instance Exception UmacException

foreign import ccall umac64_new    :: Ptr CChar -> IO (Ptr (UmacCtx 'U64))
foreign import ccall umac64_update :: Ptr (UmacCtx 'U64) -> Ptr CChar -> CLong -> IO ()
foreign import ccall umac64_final  :: Ptr (UmacCtx 'U64) -> Ptr CChar -> Ptr CChar -> IO ()
foreign import ccall umac64_reset  :: Ptr (UmacCtx 'U64) -> IO ()

foreign import ccall umac128_new    :: Ptr CChar -> IO (Ptr (UmacCtx 'U128))
foreign import ccall umac128_update :: Ptr (UmacCtx 'U128) -> Ptr CChar -> CLong -> IO ()
foreign import ccall umac128_final  :: Ptr (UmacCtx 'U128) -> Ptr CChar -> Ptr CChar -> IO ()
foreign import ccall umac128_reset  :: Ptr (UmacCtx 'U128) -> IO ()

-- shared between 64 and 128
foreign import ccall umac_delete :: Ptr (UmacCtx sz) -> IO ()
foreign import ccall "&umac_delete" umac_delete_ptr :: FinalizerPtr (UmacCtx sz)

withUMAC :: UMAC sz -> (Ptr (UmacCtx sz) -> IO a) -> IO a
withUMAC (UMAC fp) = withForeignPtr fp

-- | Required size of key bytes for UMAC.
--
-- @
-- 'keySize' = 16
-- @
keySize :: Int
keySize = 16

-- | Required size of nonce bytes for UMAC
--
-- @
-- 'nonceSize' = 8
-- @
nonceSize :: Int
nonceSize = 8

class UmacSize sz where
  umac_new    :: Ptr CChar -> IO (Ptr (UmacCtx sz))
  umac_update :: Ptr (UmacCtx sz) -> Ptr CChar -> CLong -> IO ()
  umac_final  :: Ptr (UmacCtx sz) -> Ptr CChar -> Ptr CChar -> IO ()
  umac_reset  :: Ptr (UmacCtx sz) -> IO ()
  tagSize     :: proxy sz -> Int

instance UmacSize 'U64 where
  umac_new    = umac64_new
  umac_update = umac64_update
  umac_final  = umac64_final
  umac_reset  = umac64_reset
  tagSize   _ = 8

instance UmacSize 'U128 where
  umac_new    = umac128_new
  umac_update = umac128_update
  umac_final  = umac128_final
  umac_reset  = umac128_reset
  tagSize   _ = 16

-- | Wrapper for 'umac_new' that throws an exception in the case that
-- allocation fails.
umac_new' :: UmacSize sz => Ptr CChar -> IO (Ptr (UmacCtx sz))
umac_new' key =
  do u <- umac_new key
     when (u == nullPtr) (throwIO UmacBadAllocation)
     return u

-- | Allocate a new UMAC context initialized with the given key.
-- The key should be 'keySize' bytes long.
new :: (UmacSize sz, ByteArrayAccess key) => key -> IO (UMAC sz)
new key
  | BA.length key /= keySize = throwIO UmacBadKey
  | otherwise =
      withByteArray key $ \keyPtr ->
      mask_ $ -- ensure finalizer gets installed
      do u  <- umac_new' keyPtr
         fp <- newForeignPtr umac_delete_ptr u
         return (UMAC fp)

-- | Incorporate a chunk of input into the current 'UMAC' context.
update :: (UmacSize sz, ByteArrayAccess ba) => UMAC sz -> ba -> IO ()
update ctx input =
  withUMAC ctx        $ \ctxPtr   ->
  withByteArrayLen input $ \inputPtr inputLen ->
  umac_update ctxPtr inputPtr (fromIntegral inputLen)

-- | Compute the MAC over all the chunks that have been added so far.
-- Additionally this operation resets the UMAC context making it suitable
-- for computing another MAC.
final ::
  (UmacSize sz, ByteArray tag, ByteArrayAccess nonce) =>
  UMAC sz -> nonce -> IO tag
final ctx nonce
  | BA.length nonce /= nonceSize = throwIO UmacBadNonce
  | otherwise =
      withUMAC ctx        $ \ctxPtr   ->
      withByteArray nonce $ \noncePtr ->
      alloc (tagSize ctx) $ \tagPtr   ->
      umac_final ctxPtr tagPtr noncePtr

-- | Reset the UMAC context discarding the current state making it suitable
-- for computing a MAC on a new input.
reset :: UmacSize sz => UMAC sz -> IO ()
reset ctx = withUMAC ctx umac_reset


-- | Helper function for accessing bytes as a 'Ptr' along with the
-- length of those bytes.
withByteArrayLen :: ByteArrayAccess ba => ba -> (Ptr a -> Int -> IO b) -> IO b
withByteArrayLen ba k = withByteArray ba $ \ptr -> k ptr (BA.length ba)

------------------------------------------------------------------------

-- | Compute the complete MAC for an input resented as a series of chunks.
--
-- Key must have length 'keySize', Nonce must have length 'nonceSize'
--
-- The division of chunks is immaterial.
compute :: forall proxy t sz chunk key nonce tag.
  (UmacSize sz, Foldable t, ByteArrayAccess chunk,
   ByteArrayAccess nonce, ByteArrayAccess key, ByteArray tag) =>
  proxy sz {- ^ proxy to determine MAC length -} ->
  t chunk  {- ^ input chunks                  -} ->
  key      {- ^ key                           -} ->
  nonce    {- ^ nonce                         -} ->
  tag      {- ^ computed MAC                  -}
compute sz input key nonce
  | BA.length nonce /= nonceSize = throw UmacBadNonce
  | BA.length key   /= keySize   = throw UmacBadKey
  | otherwise =
      allocAndFreeze (tagSize sz) $ \tagPtr   ->
      withByteArray key           $ \keyPtr   ->
      withByteArray nonce         $ \noncePtr ->
      bracket (umac_new' keyPtr) umac_delete $ \ctxPtr ->
      do for_ input $ \chunk ->
           withByteArrayLen chunk $ \chunkPtr chunkLen ->
             umac_update ctxPtr chunkPtr (fromIntegral chunkLen)
         umac_final (ctxPtr :: Ptr (UmacCtx sz)) tagPtr noncePtr

-- | This is 'compute' specialized to a 64-bit MAC output
compute64 ::
  (Foldable t, ByteArrayAccess chunk, ByteArrayAccess nonce,
   ByteArrayAccess key, ByteArray tag) =>
  t chunk {- ^ input chunks -} ->
  key     {- ^ key          -} ->
  nonce   {- ^ nonce        -} ->
  tag     {- ^ computed MAC -}
compute64 = compute (Proxy :: Proxy 'U64)

-- | This is 'compute' specialized to a 128-bit MAC output
compute128 ::
  (Foldable t, ByteArrayAccess chunk, ByteArrayAccess nonce,
   ByteArrayAccess key, ByteArray tag) =>
  t chunk {- ^ input chunks -} ->
  key     {- ^ key          -} ->
  nonce   {- ^ nonce        -} ->
  tag     {- ^ computed MAC -}
compute128 = compute (Proxy :: Proxy 'U128)

{-# SPECIALIZE compute64  :: [S.ByteString] -> S.ByteString -> S.ByteString -> S.ByteString #-}
{-# SPECIALIZE compute128 :: [S.ByteString] -> S.ByteString -> S.ByteString -> S.ByteString #-}
