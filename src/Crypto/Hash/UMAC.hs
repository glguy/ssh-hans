{-# LANGUAGE ForeignFunctionInterface #-}

module Crypto.Hash.UMAC
  ( UMAC
  , new
  , update
  , final
  , reset

  , compute
  ) where

import Control.Exception
import Data.Functor
import Data.ByteArray as BA
import Foreign.C
import Foreign.ForeignPtr
import Foreign.Ptr

import System.IO.Unsafe
import Data.Foldable (traverse_)

------------------------------------------------------------------------

data UmacCtx

foreign import ccall umac_new    :: Ptr CChar -> IO (Ptr UmacCtx)
foreign import ccall umac_update :: Ptr UmacCtx -> Ptr CChar -> CLong -> IO CInt
foreign import ccall umac_final  :: Ptr UmacCtx -> Ptr CChar -> Ptr CChar -> IO CInt
foreign import ccall umac_reset  :: Ptr UmacCtx -> IO CInt
foreign import ccall "&umac_delete" umac_delete_ptr :: FinalizerPtr UmacCtx

newtype UMAC = UMAC (ForeignPtr UmacCtx)

withUMAC :: UMAC -> (Ptr UmacCtx -> IO a) -> IO a
withUMAC (UMAC fp) = withForeignPtr fp

new :: ByteArrayAccess key => key -> IO UMAC
new key
  | BA.length key /= 16 = fail "UMAC.new: key must be 16 bytes"
  | otherwise =
      withByteArray key $ \keyPtr ->
      mask_ $ -- ensure finalizer gets installed
      do u <- umac_new keyPtr
         fp <- newForeignPtr umac_delete_ptr u
         return (UMAC fp)

update :: ByteArrayAccess ba => UMAC -> ba -> IO ()
update ctx input =
  withUMAC ctx        $ \ctxPtr   ->
  withByteArray input $ \inputPtr ->
  void (umac_update ctxPtr inputPtr (fromIntegral (BA.length input)))

final ::
  (ByteArray tag, ByteArrayAccess nonce) =>
  UMAC -> nonce -> IO tag
final ctx nonce
  | BA.length nonce /= 8 = fail "UMAC.final: nonce must be 8 bytes"
  | otherwise =
      withUMAC ctx        $ \ctxPtr   ->
      alloc 8             $ \tagPtr   ->
      withByteArray nonce $ \noncePtr -> -- 8
      void (umac_final ctxPtr tagPtr noncePtr)

reset :: UMAC -> IO ()
reset ctx = void (withUMAC ctx umac_reset)

------------------------------------------------------------------------

compute ::
  (ByteArrayAccess chunk, ByteArrayAccess nonce, ByteArrayAccess key, ByteArray tag) =>
  [chunk] -> key -> nonce -> tag
compute input key nonce = unsafePerformIO $
  do u <- new key
     traverse_ (update u) input
     final u nonce
