module Network.SSH.Named where

import Data.ByteString.Short
import Data.List (find)

data Named a = Named
  { nameOf     :: ShortByteString
  , namedThing :: a
  } deriving (Show, Read)

instance Functor Named where
  fmap f (Named x y) = Named x (f y)

lookupNamed :: [Named a] -> ShortByteString -> Maybe a
lookupNamed xs n = fmap namedThing (find (\x -> nameOf x == n) xs)
