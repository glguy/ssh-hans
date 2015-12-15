SSH Hans
========

A Haskell implementation of the SSH V2 Protocol.

Build the library and the example server with

    ln -s stack.ghc-7.10.yaml stack.yaml
    stack build

See `server/README.md` for info on the example server.

Bugs
----

Some OpenSSH 5.3 servers advertise support for "hmac-sha2-512", but
kex fails when this algorithm is selected for MAC in either
direction. According to OpenSSH docs [1], support for "hmac-sha2-512"
was not added until version 5.9, so I'm not sure why 5.3 servers are
advertising support.

[1] http://www.openssh.com/txt/release-5.9
