module UnixTerminalFlags where

#include <termios.h>

import Openpty
import Network.SSH.TerminalModes
import Data.Word
import Data.Bits

setIx :: Int -> a -> [a] -> [a]
setIx n _ xs | n < 0 = xs
setIx 0 x (_:ys) = x:ys
setIx n x (y:ys) = y:setIx (n-1) x ys
setIx _ _ []     = []

setCC :: Int -> Word32 -> Termios -> Termios
setCC ix arg termios = termios { c_cc = setIx ix (fromIntegral arg) (c_cc termios) }

setInput :: Tcflag_t -> Word32 -> Termios -> Termios
setInput _    0 termios = termios
setInput flag _ termios = termios { c_iflag = flag .|. c_iflag termios }

setLocal :: Tcflag_t -> Word32 -> Termios -> Termios
setLocal _    0 termios = termios
setLocal flag _ termios = termios { c_lflag = flag .|. c_lflag termios }

setOutput :: Tcflag_t -> Word32 -> Termios -> Termios
setOutput _    0 termios = termios
setOutput flag _ termios = termios { c_oflag = flag .|. c_oflag termios }

setControl :: Tcflag_t -> Word32 -> Termios -> Termios
setControl _    0 termios = termios
setControl flag _ termios = termios { c_cflag = flag .|. c_cflag termios }

setISpeed :: Word32 -> Termios -> Termios
setISpeed arg termios = termios { c_ispeed = fromIntegral arg }

setOSpeed :: Word32 -> Termios -> Termios
setOSpeed arg termios = termios { c_ospeed = fromIntegral arg }

ignore :: Word32 -> Termios -> Termios
ignore _ termios = termios

setTerminalFlag :: TerminalFlag -> Word32 -> Termios -> Termios
setTerminalFlag flag =
  case flag of
    TTY_OP_END     -> ignore -- shouldn't actually happen
    VINTR          -> setCC #{const VINTR}
    VQUIT          -> setCC #{const VQUIT}
    VERASE         -> setCC #{const VERASE}
    VKILL          -> setCC #{const VKILL}
    VEOF           -> setCC #{const VEOF}
    VEOL           -> setCC #{const VEOL}
    VEOL2          -> setCC #{const VEOL2}
    VSTART         -> setCC #{const VSTART}
    VSTOP          -> setCC #{const VSTOP}
    VSUSP          -> setCC #{const VSUSP}
#ifdef VDSUSP
    VDSUSP         -> setCC #{const VDSUSP} -- OS X
#else
    VDSUSP         -> ignore
#endif
    VREPRINT       -> setCC #{const VREPRINT}
    VWERASE        -> setCC #{const VWERASE}
    VLNEXT         -> setCC #{const VLNEXT}
    VFLUSH         -> ignore
    VSWTCH         -> ignore
#ifdef VSTATUS
    VSTATUS        -> setCC #{const VSTATUS} -- OS X
#else
    VSTATUS        -> ignore
#endif
    VDISCARD       -> setCC #{const VDISCARD}

    IGNPAR         -> setInput #{const IGNPAR}
    PARMRK         -> setInput #{const PARMRK}
    INPCK          -> setInput #{const INPCK}
    ISTRIP         -> setInput #{const ISTRIP}
    INLCR          -> setInput #{const INLCR}
    IGNCR          -> setInput #{const IGNCR}
    ICRNL          -> setInput #{const ICRNL}
    IUCLC          -> ignore
    IXON           -> setInput #{const IXON}
    IXANY          -> setInput #{const IXANY}
    IXOFF          -> setInput #{const IXOFF}
    IMAXBEL        -> setInput #{const IMAXBEL}

    ISIG           -> setLocal #{const ISIG}
    ICANON         -> setLocal #{const ICANON}
    XCASE          -> ignore
    ECHO           -> setLocal #{const ECHO}
    ECHOE          -> setLocal #{const ECHOE}
    ECHOK          -> setLocal #{const ECHOK}
    ECHONL         -> setLocal #{const ECHONL}
    NOFLSH         -> setLocal #{const NOFLSH}
    TOSTOP         -> setLocal #{const TOSTOP}
    IEXTEN         -> setLocal #{const IEXTEN}
    ECHOCTL        -> setLocal #{const ECHOCTL}
    ECHOKE         -> setLocal #{const ECHOKE}
    PENDIN         -> setLocal #{const PENDIN}

    OPOST          -> setOutput #{const OPOST}
    OLCUC          -> ignore
    ONLCR          -> setOutput #{const ONLCR}
    OCRNL          -> setOutput #{const OCRNL}
    ONOCR          -> setOutput #{const ONOCR}
    ONLRET         -> setOutput #{const ONLRET}

    CS7            -> setControl #{const CS7}
    CS8            -> setControl #{const CS8}
    PARENB         -> setControl #{const PARENB}
    PARODD         -> setControl #{const PARODD}

    TTY_OP_ISPEED  -> setISpeed
    TTY_OP_OSPEED  -> setOSpeed
