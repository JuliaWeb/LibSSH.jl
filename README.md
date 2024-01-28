# LibSSH.jl

[![docs-dev](https://img.shields.io/badge/docs-dev-blue.svg)](https://jameswrigley.github.io/LibSSH.jl/dev)

A Julia wrapper for [libssh](https://www.libssh.org). Sneak peak:
```julia
import LibSSH as ssh

session = ssh.Session("foo.com")
ssh.userauth_password(session, "password")
close(session)
```

See the docs for more information.