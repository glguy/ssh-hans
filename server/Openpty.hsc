{-# LANGUAGE ForeignFunctionInterface #-}

-- Import @openpty@.
#ifdef __APPLE__
#include <util.h>
#elif __linux__
#include <pty.h>
#else
#error "Can't find openpty"
#endif

#include <unistd.h>

module Openpty where

import Control.Applicative
import System.Posix.Types (Fd(Fd))
import Data.Word

import Foreign.C
import Foreign.Ptr
import Foreign.Marshal
import Foreign.Storable

foreign import ccall unsafe "openpty"
  c_openpty :: Ptr CInt -> Ptr CInt -> CString -> Ptr Termios -> Ptr Winsize -> IO CInt

foreign import ccall unsafe "ioctl"
  c_ioctl_winsize :: CInt -> CULong -> Ptr Winsize -> IO CInt

data Winsize = Winsize { wsRow, wsCol, wsXPixel, wsYPixel :: CUShort }

type Tcflag_t = #{type tcflag_t}
type Cc_t     = #{type cc_t}
type Speed_t  = #{type speed_t}

nccs :: Int
nccs = #{const NCCS}

data Termios = Termios
  { c_iflag, c_oflag, c_cflag, c_lflag :: Tcflag_t
  , c_cc :: [Cc_t]
  , c_ispeed, c_ospeed :: Speed_t
  }

defaultTermios :: Termios
defaultTermios =
  Termios
    #{const TTYDEF_IFLAG}
    #{const TTYDEF_OFLAG}
    #{const TTYDEF_CFLAG}
    #{const TTYDEF_LFLAG}
    [#{const CEOF}, #{const CEOL}, #{const CEOL}, #{const CERASE}, #{const CWERASE},
     #{const CKILL}, #{const CREPRINT}, #{const _POSIX_VDISABLE}, #{const CINTR},
     #{const CQUIT}, #{const CSUSP}, #{const CDSUSP}, #{const CSTART}, #{const CSTOP},
     #{const CLNEXT}, #{const CDISCARD}, #{const CMIN}, #{const CTIME}, #{const CSTATUS},
     #{const _POSIX_VDISABLE}]
     #{const TTYDEF_SPEED}
     #{const TTYDEF_SPEED}

instance Storable Winsize where
  sizeOf _ = #{size struct winsize}
  alignment _ = alignment (undefined :: CUShort)
  poke p (Winsize r c x y) =
    do #{poke struct winsize, ws_row} p r
       #{poke struct winsize, ws_col} p c
       #{poke struct winsize, ws_xpixel} p x
       #{poke struct winsize, ws_ypixel} p y
  peek p = Winsize
       <$> #{peek struct winsize, ws_row} p
       <*> #{peek struct winsize, ws_col} p
       <*> #{peek struct winsize, ws_xpixel} p
       <*> #{peek struct winsize, ws_ypixel} p

instance Storable Termios where
  sizeOf _ = #{size struct termios}
  alignment _ = alignment (undefined :: Tcflag_t)
  poke p termios =
    do #{poke struct termios, c_iflag} p (c_iflag termios)
       #{poke struct termios, c_oflag} p (c_oflag termios)
       #{poke struct termios, c_cflag} p (c_cflag termios)
       #{poke struct termios, c_lflag} p (c_lflag termios)
       pokeArray (#{ptr struct termios, c_cc} p) (c_cc termios)
       #{poke struct termios, c_ispeed} p (c_ispeed termios)
       #{poke struct termios, c_ospeed} p (c_ospeed termios)
  peek p = Termios
       <$> #{peek struct termios, c_iflag} p
       <*> #{peek struct termios, c_oflag} p
       <*> #{peek struct termios, c_cflag} p
       <*> #{peek struct termios, c_lflag} p
       <*> peekArray nccs (#{ptr struct termios, c_cc} p)
       <*> #{peek struct termios, c_ispeed} p
       <*> #{peek struct termios, c_ospeed} p

openpty ::
  Maybe String  {- ^ optional file name      -} ->
  Maybe Winsize {- ^ optional window size    -} ->
  Maybe Termios {- ^ optional terminal flags -} ->
  IO (Fd, Fd)   {- ^ (master fd, slave fd)   -}
openpty name winsize termios =
  alloca              $ \masterPtr ->
  alloca              $ \slavePtr  ->
  withCStringMb name  $ \namePtr   ->
  withMb winsize      $ \winPtr    ->
  withMb termios      $ \termPtr   ->
    do throwErrnoIfMinus1_ "openpty"
         (c_openpty masterPtr slavePtr namePtr termPtr winPtr)
       masterFd <- peek masterPtr
       slaveFd  <- peek slavePtr
       return (Fd masterFd, Fd slaveFd)

  where
  withMb Nothing  k = k nullPtr
  withMb (Just x) k = with x k

  withCStringMb Nothing    k = k nullPtr
  withCStringMb (Just str) k = withCString str k


changePtyWinsize :: Fd -> Winsize -> IO ()
changePtyWinsize (Fd fd) winsize =
  throwErrnoIfMinus1_ "ioctl" $
  with winsize        $
  c_ioctl_winsize fd #{const TIOCSWINSZ}
