module Network.SSH.TerminalModes where

import Data.List
import qualified Data.ByteString as S
import Data.Serialize.Get
import Data.Word

parseTerminalModes :: S.ByteString -> Either String [(TerminalFlag, Word32)]
parseTerminalModes = runGet loop
  where
  loop =
    do tag <- getWord8
       case codeToTermFlag tag of
         Nothing         -> return []
         Just TTY_OP_END -> return []
         Just flag       -> do arg <- getWord32be
                               rest <- loop
                               return ((flag,arg):rest)

data TerminalFlag
  = TTY_OP_END | VINTR | VQUIT | VERASE | VKILL | VEOF | VEOL | VEOL2 | VSTART
  | VSTOP | VSUSP | VDSUSP | VREPRINT | VWERASE | VLNEXT | VFLUSH | VSWTCH
  | VSTATUS | VDISCARD | IGNPAR | PARMRK | INPCK | ISTRIP | INLCR | IGNCR
  | ICRNL | IUCLC | IXON | IXANY | IXOFF | IMAXBEL | ISIG | ICANON | XCASE
  | ECHO | ECHOE | ECHOK | ECHONL | NOFLSH | TOSTOP | IEXTEN | ECHOCTL | ECHOKE
  | PENDIN | OPOST | OLCUC | ONLCR | OCRNL | ONOCR | ONLRET | CS7 | CS8
  | PARENB | PARODD | TTY_OP_ISPEED | TTY_OP_OSPEED
 deriving (Read, Show, Ord, Eq)


codeToTermFlag :: Word8 -> Maybe TerminalFlag
codeToTermFlag code =
  case code of
    0    -> Just TTY_OP_END
    1    -> Just VINTR
    2    -> Just VQUIT
    3    -> Just VERASE
    4    -> Just VKILL
    5    -> Just VEOF
    6    -> Just VEOL
    7    -> Just VEOL2
    8    -> Just VSTART
    9    -> Just VSTOP
    10   -> Just VSUSP
    11   -> Just VDSUSP
    12   -> Just VREPRINT
    13   -> Just VWERASE
    14   -> Just VLNEXT
    15   -> Just VFLUSH
    16   -> Just VSWTCH
    17   -> Just VSTATUS
    18   -> Just VDISCARD
    30   -> Just IGNPAR
    31   -> Just PARMRK
    32   -> Just INPCK
    33   -> Just ISTRIP
    34   -> Just INLCR
    35   -> Just IGNCR
    36   -> Just ICRNL
    37   -> Just IUCLC
    38   -> Just IXON
    39   -> Just IXANY
    40   -> Just IXOFF
    41   -> Just IMAXBEL
    50   -> Just ISIG
    51   -> Just ICANON
    52   -> Just XCASE
    53   -> Just ECHO
    54   -> Just ECHOE
    55   -> Just ECHOK
    56   -> Just ECHONL
    57   -> Just NOFLSH
    58   -> Just TOSTOP
    59   -> Just IEXTEN
    60   -> Just ECHOCTL
    61   -> Just ECHOKE
    62   -> Just PENDIN
    70   -> Just OPOST
    71   -> Just OLCUC
    72   -> Just ONLCR
    73   -> Just OCRNL
    74   -> Just ONOCR
    75   -> Just ONLRET
    90   -> Just CS7
    91   -> Just CS8
    92   -> Just PARENB
    93   -> Just PARODD
    128  -> Just TTY_OP_ISPEED
    129  -> Just TTY_OP_OSPEED


terminalFlagToCode :: TerminalFlag -> Word8
terminalFlagToCode flag =
  case flag of
    TTY_OP_END     -> 0
    VINTR          -> 1
    VQUIT          -> 2
    VERASE         -> 3
    VKILL          -> 4
    VEOF           -> 5
    VEOL           -> 6
    VEOL2          -> 7
    VSTART         -> 8
    VSTOP          -> 9
    VSUSP          -> 10
    VDSUSP         -> 11
    VREPRINT       -> 12
    VWERASE        -> 13
    VLNEXT         -> 14
    VFLUSH         -> 15
    VSWTCH         -> 16
    VSTATUS        -> 17
    VDISCARD       -> 18
    IGNPAR         -> 30
    PARMRK         -> 31
    INPCK          -> 32
    ISTRIP         -> 33
    INLCR          -> 34
    IGNCR          -> 35
    ICRNL          -> 36
    IUCLC          -> 37
    IXON           -> 38
    IXANY          -> 39
    IXOFF          -> 40
    IMAXBEL        -> 41
    ISIG           -> 50
    ICANON         -> 51
    XCASE          -> 52
    ECHO           -> 53
    ECHOE          -> 54
    ECHOK          -> 55
    ECHONL         -> 56
    NOFLSH         -> 57
    TOSTOP         -> 58
    IEXTEN         -> 59
    ECHOCTL        -> 60
    ECHOKE         -> 61
    PENDIN         -> 62
    OPOST          -> 70
    OLCUC          -> 71
    ONLCR          -> 72
    OCRNL          -> 73
    ONOCR          -> 74
    ONLRET         -> 75
    CS7            -> 90
    CS8            -> 91
    PARENB         -> 92
    PARODD         -> 93
    TTY_OP_ISPEED  -> 128
    TTY_OP_OSPEED  -> 129

{-
8.  Encoding of Terminal Modes

   All 'encoded terminal modes' (as passed in a pty request) are encoded
   into a byte stream.  It is intended that the coding be portable
   across different environments.  The stream consists of opcode-
   argument pairs wherein the opcode is a byte value.  Opcodes 1 to 159
   have a single uint32 argument.  Opcodes 160 to 255 are not yet
   defined, and cause parsing to stop (they should only be used after
   any other data).  The stream is terminated by opcode TTY_OP_END
   (0x00).

   The client SHOULD put any modes it knows about in the stream, and the
   server MAY ignore any modes it does not know about.  This allows some
   degree of machine-independence, at least between systems that use a
   POSIX-like tty interface.  The protocol can support other systems as
   well, but the client may need to fill reasonable values for a number
   of parameters so the server pty gets set to a reasonable mode (the
   server leaves all unspecified mode bits in their default values, and
   only some combinations make sense).

   The naming of opcode values mostly follows the POSIX terminal mode
   flags.  The following opcode values have been defined.  Note that the
   values given below are in decimal format for readability, but they
   are actually byte values.

          opcode  mnemonic       description
          ------  --------       -----------
          0     TTY_OP_END  Indicates end of options.
          1     VINTR       Interrupt character; 255 if none.  Similarly
                             for the other characters.  Not all of these
                             characters are supported on all systems.
          2     VQUIT       The quit character (sends SIGQUIT signal on
                             POSIX systems).
          3     VERASE      Erase the character to left of the cursor.
          4     VKILL       Kill the current input line.
          5     VEOF        End-of-file character (sends EOF from the
                             terminal).
          6     VEOL        End-of-line character in addition to
                             carriage return and/or linefeed.
          7     VEOL2       Additional end-of-line character.
          8     VSTART      Continues paused output (normally
                             control-Q).
          9     VSTOP       Pauses output (normally control-S).
          10    VSUSP       Suspends the current program.
          11    VDSUSP      Another suspend character.



Ylonen & Lonvick            Standards Track                    [Page 19]

RFC 4254                SSH Connection Protocol             January 2006


          12    VREPRINT    Reprints the current input line.
          13    VWERASE     Erases a word left of cursor.
          14    VLNEXT      Enter the next character typed literally,
                             even if it is a special character
          15    VFLUSH      Character to flush output.
          16    VSWTCH      Switch to a different shell layer.
          17    VSTATUS     Prints system status line (load, command,
                             pid, etc).
          18    VDISCARD    Toggles the flushing of terminal output.
          30    IGNPAR      The ignore parity flag.  The parameter
                             SHOULD be 0 if this flag is FALSE,
                             and 1 if it is TRUE.
          31    PARMRK      Mark parity and framing errors.
          32    INPCK       Enable checking of parity errors.
          33    ISTRIP      Strip 8th bit off characters.
          34    INLCR       Map NL into CR on input.
          35    IGNCR       Ignore CR on input.
          36    ICRNL       Map CR to NL on input.
          37    IUCLC       Translate uppercase characters to
                             lowercase.
          38    IXON        Enable output flow control.
          39    IXANY       Any char will restart after stop.
          40    IXOFF       Enable input flow control.
          41    IMAXBEL     Ring bell on input queue full.
          50    ISIG        Enable signals INTR, QUIT, [D]SUSP.
          51    ICANON      Canonicalize input lines.
          52    XCASE       Enable input and output of uppercase
                             characters by preceding their lowercase
                             equivalents with "\".
          53    ECHO        Enable echoing.
          54    ECHOE       Visually erase chars.
          55    ECHOK       Kill character discards current line.
          56    ECHONL      Echo NL even if ECHO is off.
          57    NOFLSH      Don't flush after interrupt.
          58    TOSTOP      Stop background jobs from output.
          59    IEXTEN      Enable extensions.
          60    ECHOCTL     Echo control characters as ^(Char).
          61    ECHOKE      Visual erase for line kill.
          62    PENDIN      Retype pending input.
          70    OPOST       Enable output processing.
          71    OLCUC       Convert lowercase to uppercase.
          72    ONLCR       Map NL to CR-NL.
          73    OCRNL       Translate carriage return to newline
                             (output).
          74    ONOCR       Translate newline to carriage
                             return-newline (output).
          75    ONLRET      Newline performs a carriage return
                             (output).
          90    CS7         7 bit mode.
          91    CS8         8 bit mode.
          92    PARENB      Parity enable.
          93    PARODD      Odd parity, else even.

          128 TTY_OP_ISPEED  Specifies the input baud rate in
                              bits per second.
          129 TTY_OP_OSPEED  Specifies the output baud rate in
                              bits per second.
-}
