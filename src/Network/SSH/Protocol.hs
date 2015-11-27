{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.Protocol (
    getBoolean,  putBoolean
  , getMpInt,    putMpInt
  , getUnsigned, putUnsigned
  , getString,   putString
  , getNameList, putNameList
  ) where

import           Data.Bits ( shiftL, shiftR, testBit )
import           Data.ByteString.Short (ShortByteString, fromShort, toShort)
import qualified Data.ByteString.Short as Short
import qualified Data.ByteString as S
import           Data.Char ( ord )
import           Data.List ( intersperse )
import           Data.Serialize
                     ( Putter, Get, getBytes, putByteString
                     , getWord8, putWord8, putWord32be, getWord32be )
import           Data.Word ( Word8, Word32 )


-- Rendering -------------------------------------------------------------------

putBoolean :: Putter Bool
putBoolean True  = putWord8 1
putBoolean False = putWord8 0

putMpInt :: Putter Integer
putMpInt i =
  do let (len,bytes) = unpack i
     putWord32be len
     mapM_ putWord8 bytes

unpack :: Integer -> (Word32, [Word8])
unpack 0 = (0,[])
unpack n0 = go 0 [] n0
  where
  go !len bytes n
    | -0x80 <= n && n < 0x80 = (len1, n8 : bytes)
    | otherwise              = go len1 (n8 : bytes) $! shiftR n 8
    where
    !n8      = fromInteger n
    !len1    = len + 1


putUnsigned :: Int -> Putter Integer
putUnsigned size val = mapM_ putWord8 (go [] size val)
  where
  go acc 0 _ = acc
  go acc sz n = go (n8 : acc) (sz-1) $! n`shiftR`8
     where !n8 = fromInteger n

putNameList :: Putter [ShortByteString]
putNameList names =
  do let len | null names = 0
             | otherwise  = sum (map Short.length names)
                          + length names - 1 -- commas
     putWord32be (fromIntegral len)
     mapM_ putByteString (intersperse "," (map fromShort names))

putString :: Putter S.ByteString
putString bytes =
  do putWord32be (fromIntegral (S.length bytes))
     putByteString bytes


-- Parsing ---------------------------------------------------------------------

getBoolean :: Get Bool
getBoolean  =
  do b <- getWord8
     return $! b /= 0

getMpInt :: Get Integer
getMpInt  =
  do numBytes <- getWord32be
     bytes    <- getBytes (fromIntegral numBytes)
     return $! case S.uncons bytes of
                 Nothing -> 0
                 Just (msb,rest) -> S.foldl' aux msb' rest
                   where
                      aux acc b = acc`shiftL`8 + fromIntegral b
                      msb' | testBit msb 7 = toInteger msb - 0x100
                           | otherwise     = toInteger msb

getUnsigned :: Int -> Get Integer
getUnsigned n = S.foldl' aux 0 <$> getBytes n
  where
  aux acc n = acc`shiftL`8 + fromIntegral n

getNameList :: Get [ShortByteString]
getNameList  =
  do len   <- getWord32be
     bytes <- getBytes (fromIntegral len)
     return (map toShort (S.split comma bytes))
  where
  comma = fromIntegral (ord ',')

getString :: Get S.ByteString
getString  =
  do len <- getWord32be
     getBytes (fromIntegral len)
