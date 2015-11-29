{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Compression
  ( Compression(..)
  , allCompression
  , compression_none
  , compression_zlib
  ) where

#include <zlib.h>

import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Unsafe as U
import           Control.Monad
import           Control.Exception
import           Foreign
import           Foreign.C.Types
import           Foreign.C.String

import Network.SSH.Named

data Compression = Compression
  { makeCompress   :: IO (S.ByteString -> IO L.ByteString)
  , makeDecompress :: IO (S.ByteString -> IO L.ByteString)
  }

allCompression :: [Named Compression]
allCompression = [compression_none, compression_zlib]

compression_none :: Named Compression
compression_none = Named "none" (Compression mknoop mknoop)
  where mknoop = return (return . L.fromStrict)

compression_zlib :: Named Compression
compression_zlib = Named "zlib" (Compression mkZlibCompressor mkZlibDecompressor)

------------------------------------------------------------------------
-- Local minimalistic binding to zlib
------------------------------------------------------------------------

-- | Type used to tag pointers to @z_stream@
data ZStream

-- | Returns values from zlib
newtype ZError = ZError CInt deriving (Eq, Show)
instance Exception ZError
#enum ZError, ZError, Z_OK, Z_BUF_ERROR

-- | Flush arguments instruct 'inflate' and 'deflate' on output behavior.
newtype ZFlush = ZFlush CInt
#enum ZFlush, ZFlush, Z_PARTIAL_FLUSH

-- | Allocate a new, uninitialized 'ZStream'
newZStream :: IO (ForeignPtr ZStream)
newZStream = mallocForeignPtrBytes #{size z_stream}

-- | Assign a buffer to be used as input
setInput :: Ptr ZStream -> CStringLen -> IO ()
setInput z (p,n) =
  do #{poke z_stream, avail_in} z (fromIntegral n :: CUInt)
     #{poke z_stream, next_in } z p

-- | Assign a buffer to be used as output
setOutput :: Ptr ZStream -> CStringLen -> IO ()
setOutput z (p,n) =
  do #{poke z_stream, avail_out} z (fromIntegral n :: CUInt)
     #{poke z_stream, next_out } z p

-- | Get number of bytes available in the output buffer
getAvailOut :: Ptr ZStream -> IO CUInt
getAvailOut = #{peek z_stream, avail_out}

foreign import ccall "ssh_hans_zlib_inflateInit" inflateInit :: Ptr ZStream -> IO ZError
foreign import ccall "zlib.h inflate" inflate :: Ptr ZStream -> ZFlush -> IO ZError
foreign import ccall "zlib.h &inflateEnd" inflateEndPtr :: FunPtr (Ptr ZStream -> IO ())

foreign import ccall "ssh_hans_zlib_deflateInit" deflateInit :: Ptr ZStream -> IO ZError
foreign import ccall "zlib.h deflate" deflate :: Ptr ZStream -> ZFlush -> IO ZError
foreign import ccall "zlib.h &deflateEnd" deflateEndPtr :: FunPtr (Ptr ZStream -> IO ())

------------------------------------------------------------------------


-- | Takes an action that returns a Zlib return value. If an error
-- value is returned then that value is raised as a 'ZError' exception.
throwZ :: IO ZError -> IO ()
throwZ m =
  do result <- m
     unless (result == zOk) (throwIO result)

-- | Execute an initializing procedure on a ForeignPtr managed pointer.
-- If initialization is successful a finalizer is added to the ForeignPtr.
-- Asynchronous exceptions are masked during initialization.
setupForeignPtr ::
  (Ptr a -> IO ()) {- ^ initializer -} ->
  FinalizerPtr a   {- ^ finalizer   -} ->
  ForeignPtr a -> IO ()
setupForeignPtr start finish fp =
  mask_ $ do withForeignPtr fp start
             addForeignPtrFinalizer finish fp

-- | Contruct a new function suitable for decompressing a stream.
-- Each decompression will update the zlib state.
mkZlibDecompressor :: IO (S.ByteString -> IO L.ByteString)
mkZlibDecompressor =
  do fz <- newZStream
     setupForeignPtr (throwZ . inflateInit) inflateEndPtr fz
     return (zlibDriver inflate fz)

-- | Contruct a new function suitable for compressing a stream.
-- Each compression will update the zlib state.
mkZlibCompressor :: IO (S.ByteString -> IO L.ByteString)
mkZlibCompressor =
  do fz <- newZStream
     setupForeignPtr (throwZ . deflateInit) deflateEndPtr fz
     return (zlibDriver deflate fz)

-- | This adds the input bytes to the already initialized z_stream
-- and then calls the provided 'inflate' or 'deflate' operation
-- until all output is emitted.
zlibDriver ::
  (Ptr ZStream -> ZFlush -> IO ZError) {- 'inflate' or 'deflate' -} ->
  ForeignPtr ZStream {- ^ initialized z_stream -} ->
  S.ByteString       {- ^ input bytes -} ->
  IO L.ByteString    {- ^ output bytes -}
zlibDriver flate fz input =

  -- safe: zlib doesn't modify the input buffer
  U.unsafeUseAsCStringLen input $ \inPtrLen ->

  withForeignPtr fz $ \z ->

  -- bytestrings this size will occupy 8 pages exactly
  let bufSize = 32752 in
  allocaBytes bufSize $ \buf ->

  do setInput z inPtrLen

     let loop chunks =
           do setOutput z (buf, fromIntegral bufSize)

              result <- flate z zPartialFlush
              unless (result == zOk || result == zBufError) (throwIO result)
              -- Z_BUF_ERROR is not fatal and can happen if there is no new output

              out'  <- getAvailOut z
              chunk <- S.packCStringLen (buf, bufSize - fromIntegral out')

              let chunks' = chunk : chunks
              if out' == 0 -- whole output buffer used
                 then loop chunks'
                 else return (L.fromChunks (reverse chunks'))

     loop []
