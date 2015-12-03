{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE PolyKinds #-}
{-# LANGUAGE ForeignFunctionInterface #-}

module Crypto.Hash.UMAC
  ( UMAC
  , new
  , update
  , final
  , reset

  , compute
  , compute64
  , compute128
  ) where

import Control.Exception
import Control.Monad
import Data.Proxy
import Data.ByteArray as BA
import qualified Data.ByteString as S
import Foreign.C
import Foreign.ForeignPtr
import Foreign.Ptr

import Data.Foldable (Foldable,for_)

------------------------------------------------------------------------

data USize = U64 | U128
data UmacCtx (sz :: USize)
newtype UMAC sz = UMAC (ForeignPtr (UmacCtx sz))

data UmacAllocationFailure = UmacAllocationFailure
  deriving (Show, Read, Eq, Ord)

instance Exception UmacAllocationFailure

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

class UmacSize sz where
  umac_new    :: Ptr CChar -> IO (Ptr (UmacCtx sz))
  umac_update :: Ptr (UmacCtx sz) -> Ptr CChar -> CLong -> IO ()
  umac_final  :: Ptr (UmacCtx sz) -> Ptr CChar -> Ptr CChar -> IO ()
  umac_reset  :: Ptr (UmacCtx sz) -> IO ()
  umac_tagSize :: proxy sz -> Int

instance UmacSize 'U64 where
  umac_new    = umac64_new
  umac_update = umac64_update
  umac_final  = umac64_final
  umac_reset  = umac64_reset
  umac_tagSize _ = 8

instance UmacSize 'U128 where
  umac_new    = umac128_new
  umac_update = umac128_update
  umac_final  = umac128_final
  umac_reset  = umac128_reset
  umac_tagSize _ = 16

new :: (UmacSize sz, ByteArrayAccess key) => key -> IO (UMAC sz)
new key
  | BA.length key /= 16 = fail "UMAC.new: key must be 16 bytes"
  | otherwise =
      withByteArray key $ \keyPtr ->
      mask_ $ -- ensure finalizer gets installed
      do u <- umac_new keyPtr
         when (u == nullPtr) (throwIO UmacAllocationFailure)
         fp <- newForeignPtr umac_delete_ptr u
         return (UMAC fp)

update :: (UmacSize sz, ByteArrayAccess ba) => UMAC sz -> ba -> IO ()
update ctx input =
  withUMAC ctx        $ \ctxPtr   ->
  withByteArray input $ \inputPtr ->
  umac_update ctxPtr inputPtr (fromIntegral (BA.length input))

final ::
  (UmacSize sz, ByteArray tag, ByteArrayAccess nonce) =>
  UMAC sz -> nonce -> IO tag
final ctx nonce
  | BA.length nonce /= 8 = fail "UMAC.final: nonce must be 8 bytes"
  | otherwise =
      withUMAC ctx        $ \ctxPtr   ->
      withByteArray nonce $ \noncePtr ->
      alloc (umac_tagSize ctx) $ \tagPtr   ->
      umac_final ctxPtr tagPtr noncePtr

reset :: UmacSize sz => UMAC sz -> IO ()
reset ctx = withUMAC ctx umac_reset

------------------------------------------------------------------------

compute :: forall proxy t sz chunk key nonce tag.
  (UmacSize sz, Foldable t, ByteArrayAccess chunk,
   ByteArrayAccess nonce, ByteArrayAccess key, ByteArray tag) =>
  proxy sz -> t chunk -> key -> nonce -> tag
compute sz input key nonce
  | BA.length nonce /= 8  = error "UMAC: bad nonce"
  | BA.length key   /= 16 = error "UMAC: bad key"
  | otherwise =
      allocAndFreeze (umac_tagSize sz) $ \tagPtr   ->
      withByteArray key                $ \keyPtr   ->
      withByteArray nonce              $ \noncePtr ->
      bracket (umac_new keyPtr) umac_delete $ \ctxPtr ->
      do for_ input $ \chunk ->
           withByteArray chunk $ \chunkPtr ->
             umac_update ctxPtr chunkPtr (fromIntegral (BA.length chunk))
         umac_final (ctxPtr :: Ptr (UmacCtx sz)) tagPtr noncePtr

compute64 ::
  (Foldable t, ByteArrayAccess chunk, ByteArrayAccess nonce,
   ByteArrayAccess key, ByteArray tag) =>
  t chunk -> key -> nonce -> tag
compute64 = compute (Proxy :: Proxy 'U64)

compute128 ::
  (Foldable t, ByteArrayAccess chunk, ByteArrayAccess nonce,
   ByteArrayAccess key, ByteArray tag) =>
  t chunk -> key -> nonce -> tag
compute128 = compute (Proxy :: Proxy 'U128)

{-# SPECIALIZE compute64  :: [S.ByteString] -> S.ByteString -> S.ByteString -> S.ByteString #-}
{-# SPECIALIZE compute128 :: [S.ByteString] -> S.ByteString -> S.ByteString -> S.ByteString #-}
