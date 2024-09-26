# LibSSH.jl

[![docs-stable](https://img.shields.io/badge/docs-stable-blue.svg)](https://juliaweb.github.io/LibSSH.jl/stable) [![docs-dev](https://img.shields.io/badge/docs-dev-blue.svg)](https://juliaweb.github.io/LibSSH.jl/dev) [![codecov](https://codecov.io/gh/JuliaWeb/LibSSH.jl/graph/badge.svg?token=DOvXIg3XEG)](https://codecov.io/gh/JuliaWeb/LibSSH.jl)

A Julia wrapper for [libssh](https://www.libssh.org). Sneak peak:
```julia
import LibSSH as ssh

session = ssh.Session("foo.com")
ssh.userauth_password(session, "password")
close(session)
```

See the docs for more information.
