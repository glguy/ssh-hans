SSH Server
==========

The server program `server` takes a port number as argument and
listens on the given TCP port. The server exposes these services:
- terminal connections, e.g. via `ssh localhost`: ASCII version of the
  popular Set game!
- "echo" command, e.g. via `ssh localhost echo`: echos back whatever
  you type.
- "echo" subsystem, e.g. via `ssh localhost -s echo`: echos back
  whatever you type

The server expects to find a private key in a `server_keys` file in
the directory the server is started in. This file must be in OpenSSH
format, which you get by passing `-o` to `ssh-keygen`.

The server supports key-based logins by the Unix user who is running
the server, using the keys in that users `$HOME/.ssh/authorized_keys`
file. The server also supports password logins by any user, using a
top-secret password ...

Example Usage
-------------

Copy your public key into your authorized keys file if necessary:

    cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys

Generate an OpenSSH-format `server_keys` private-key file if
necessary:

    ssh-keygen -o -N '' -f server_keys

Start the server:

    # Assumes you did `ln -s stack.ghc-8.2.1.yaml stack.yaml` in `..`.
    stack build
    stack exec ssh-hans-example-server 2200

Connect to the server and play set:

    ssh localhost -p 2200

Connect to the echo service:

    # As an exec request:
    ssh localhost -p 2200 echo
    # Or as a subsystem:
    ssh localhost -p 2200 -s echo
