{-# LANGUAGE OverloadedStrings #-}

module Network.SSH.Protocol (
    getBoolean,  putBoolean
  , getMpInt,    putMpInt
  , getUnsigned, putUnsigned
  , getString,   putString
  , getNameList, putNameList
  ) where

import           Data.Bits ( shiftL, shiftR, (.&.), testBit )
import qualified Data.ByteString as S
import           Data.Char ( ord )
import           Data.List ( intersperse )
import           Data.Serialize
                     ( Putter, Get, label, isolate, getBytes, putByteString
                     , getWord8, putWord8, putWord32be, getWord32be )
import           Data.Word ( Word8, Word32 )

import Debug.Trace


-- Rendering -------------------------------------------------------------------

putBoolean :: Putter Bool
putBoolean True  = putWord8 1
putBoolean False = putWord8 0

putMpInt :: Putter Integer
putMpInt i =
  do putWord32be len
     mapM_ putWord8 bytes
  where
  (len,bytes) = unpack i

unpack :: Integer -> (Word32, [Word8])
unpack  = go 0 []
  where
  go len bytes n
    | abs n < 0xff = finalize len bytes n
    | otherwise    = let byte = fromInteger (n .&. 0xff)
                         n'   = n `shiftR` 8
                         len' = len + 1
                      in go len' (byte : bytes) (byte `seq` len' `seq` n')

  finalize len bytes n
    | n == 0               = (len,                     bytes)
    | n > 0 && testBit n 7 = (len + 2, 0 : fromInteger n : bytes)
    | otherwise            = (len + 1,     fromInteger n : bytes)

putUnsigned :: Int -> Putter Integer
putUnsigned size val =
  do let (padding,bytes) = go [] val
     mapM_ putWord8 padding
     mapM_ putWord8 bytes
  where

  go acc n
    | n <= 0xff = let res    = reverse (fromInteger n : acc)
                      len    = length res
                      padLen = size - len
                   in (replicate padLen 0, res)

    | otherwise = let acc' = fromInteger (n .&. 0xff) : acc
                   in go acc' (acc' `seq` (n `shiftR` 8))

putNameList :: Putter [S.ByteString]
putNameList names =
  do let len | null names = 0
             | otherwise  = sum (map S.length names)
                          + length names - 1 -- commas
     putWord32be (fromIntegral len)
     mapM_ putByteString (intersperse "," names)

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

     if numBytes == 0
        then return 0
        else isolate (fromIntegral numBytes) $
               do w <- getWord8
                  let msb | w == 0      = 0
                          | testBit w 7 = toInteger w - 0x100
                          | otherwise   = toInteger w

                  go msb (numBytes - 1)
  where
  go acc 0 =    return acc
  go acc n = do w <- getWord8
                let acc' = (acc `shiftL` 8) + fromIntegral w
                go acc' (acc' `seq` n-1)

getUnsigned :: Int -> Get Integer
getUnsigned  = go []
  where
  go acc 0 = return $! foldr step 0 acc
  go acc n = do w <- getWord8
                let acc' = w : acc
                go acc' (acc' `seq` n - 1)

  step w acc = acc `shiftL` 8 + toInteger w

getNameList :: Get [S.ByteString]
getNameList  =
  do len   <- getWord32be
     bytes <- getBytes (fromIntegral len)
     return (S.splitWith (== comma) bytes)
  where
  comma = fromIntegral (ord ',')

getString :: Get S.ByteString
getString  =
  do len <- getWord32be
     getBytes (fromIntegral len)
