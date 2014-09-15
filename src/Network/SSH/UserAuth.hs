module Network.SSH.UserAuth where

import Network.SSH.Transport


data SshUserAuthRequest = SshUserAuthRequest { sshUsername    :: !S.ByteString
                                             , sshServiceName :: !S.ByteString
                                             , sshAuthMethod  :: SshAuthMethod
                                             } deriving (Show,Eq)


-- Rendering -------------------------------------------------------------------

putSshUserAuthRequest :: Putter SshUserAuthRequest
putSshUserAuthRequest SshUserAuthRequest { .. } =
  do putWord8


-- Parsing ---------------------------------------------------------------------

getSshUserAuthRequest
