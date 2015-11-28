{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE OverloadedStrings #-}
module Network.SSH.Compression where

#include <zlib.h>

import qualified Data.ByteString as S
import qualified Data.ByteString.Lazy as L
import qualified Data.ByteString.Unsafe as U
import           Control.Monad
import           Control.Exception
import           Foreign
import           Foreign.C.Types

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

data ZStream

zstreamSize :: Int
zstreamSize = #{size z_stream}

zPartialFlush :: CInt
zPartialFlush = #{const Z_PARTIAL_FLUSH}

zCompressLevel :: CInt
zCompressLevel = #{const Z_DEFAULT_COMPRESSION}

setNextIn :: Ptr ZStream -> Ptr CChar -> IO ()
setNextIn = #{poke z_stream, next_in}

setAvailIn :: Ptr ZStream -> CUInt -> IO ()
setAvailIn = #{poke z_stream, avail_in}

setNextOut :: Ptr ZStream -> Ptr CChar -> IO ()
setNextOut = #{poke z_stream, next_out}

setAvailOut :: Ptr ZStream -> CUInt -> IO ()
setAvailOut = #{poke z_stream, avail_out}

getAvailOut :: Ptr ZStream -> IO CUInt
getAvailOut = #{peek z_stream, avail_out}

setZAlloc :: Ptr ZStream -> FunPtr (Ptr a -> CUInt -> CUInt -> IO (Ptr b)) -> IO ()
setZAlloc = #{poke z_stream, zalloc}

setZFree :: Ptr ZStream -> FunPtr (Ptr a -> Ptr b -> IO ()) -> IO ()
setZFree = #{poke z_stream, zfree}

setOpaque :: Ptr ZStream -> Ptr a -> IO ()
setOpaque = #{poke z_stream, opaque}

------------------------------------------------------------------------

-- inflateInit is a macro that calls inflateInit_
foreign import capi "zlib.h inflateInit" inflateInit :: Ptr ZStream -> IO CInt
foreign import ccall "zlib.h inflate" inflate :: Ptr ZStream -> CInt -> IO CInt
foreign import ccall "zlib.h &inflateEnd" inflateEndPtr :: FunPtr (Ptr ZStream -> IO ())

foreign import capi  "zlib.h deflateInit" deflateInit :: Ptr ZStream -> CInt -> IO CInt
foreign import ccall "zlib.h deflate" deflate :: Ptr ZStream -> CInt -> IO CInt
foreign import ccall "zlib.h &deflateEnd" deflateEndPtr :: FunPtr (Ptr ZStream -> IO ())

data ZError = ZError CInt
  deriving (Eq, Show)

instance Exception ZError

throwZ :: IO CInt -> IO ()
throwZ m =
  do result <- m
     unless (result == #{const Z_OK}) (throwIO (ZError result))

mkZlibDecompressor :: IO (S.ByteString -> IO L.ByteString)
mkZlibDecompressor =
  do fz <- newZStream
     withForeignPtr fz $ \z ->
       throwZ (inflateInit z)
     addForeignPtrFinalizer inflateEndPtr fz
     return (zlibDriver inflate fz)

mkZlibCompressor :: IO (S.ByteString -> IO L.ByteString)
mkZlibCompressor =
  do fz <- newZStream
     withForeignPtr fz $ \z ->
       throwZ (deflateInit z zCompressLevel)
     addForeignPtrFinalizer deflateEndPtr fz
     return (zlibDriver deflate fz)

-- | Allocate a new z_stream and prepare it as a valid argument
-- for deflateInit and inflateInit
newZStream :: IO (ForeignPtr ZStream)
newZStream =
  do fz <- mallocForeignPtrBytes zstreamSize
     withForeignPtr fz $ \z ->
       do setNextIn  z nullPtr
          setAvailIn z 0
          setZAlloc  z nullFunPtr
          setZFree   z nullFunPtr
          setOpaque  z nullPtr
     return fz

zlibDriver ::
  (Ptr ZStream -> CInt -> IO CInt) ->
  ForeignPtr ZStream ->
  S.ByteString ->
  IO L.ByteString
zlibDriver flate fz input =

  withForeignPtr fz $ \z ->
  U.unsafeUseAsCStringLen input $ \(inPtr, inLen) ->

  let bufSize = 32752 in
  allocaBytes bufSize $ \buf ->

  do setNextIn z inPtr
     setAvailIn z (fromIntegral inLen)

     let loop acc =
           do setNextOut z buf
              setAvailOut z (fromIntegral bufSize)
              throwZ (flate z zPartialFlush)
              out' <- getAvailOut z
              chunk <- S.packCStringLen (buf, bufSize - fromIntegral out')

              let acc' = chunk : acc
              if out' == 0
                 then loop acc'
                 else return (L.fromChunks (reverse acc'))

     loop []
