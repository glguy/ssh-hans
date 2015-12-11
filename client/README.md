SSH Client
==========

The client program `client` authenticates with a server and then
disconnects (TODO(conathan): add terminal session support):

    # Assumes you did `ln -s stack.ghc-7.10.yaml stack.yaml` in `..`.
    stack exec -- client -h
    usage: client USER SERVER_ADDR SERVER_PORT [PRIVATE_KEY]

The optional private key file must be in OpenSSH format, which you get
by passing `-o` to `ssh-keygen`.

If no keys are supplied, or none of them authenticate, the client then
prompts for a password and attempts password authentication.

Example Usage
-------------

Generate an OpenSSH-format client key file if necessary:

    ssh-keygen -o -N '' -f client_keys

Copy your public key into your authorized keys file if necessary:

    cat client_keys.pub >> ~/.ssh/authorized_keys

Connect to `localhost` with the client, using publickey
authentication:

    # Assumes you did `ln -s stack.ghc-7.10.yaml stack.yaml` in `..`.
    stack build
    # Assumes you are running an SSH server on localhost port 22.
    stack exec client `whoami` localhost 22 client_keys

Connect to `localhost` with the client, using password authentication:

    stack exec client `whoami` localhost 22
