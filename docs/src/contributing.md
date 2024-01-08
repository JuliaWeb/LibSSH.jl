# Contributing

Libssh is a fairly large project and most of the API still doesn't have
high-level wrappers in LibSSH.jl. For example:
- Reverse port forwarding
- Unix socket forwarding
- SFTP support
- SCP support

If you'd like to contribute new wrappers, the usual workflow is:
1. Add support for the feature in the [Demo server](@ref) and test it with the
   `ssh` client from OpenSSH.
2. Add client support for the feature and test it with the newly updated demo
   server.

This way we can test as much of the codebase as possible.

### Running tests

The tests can be run with `] test` as usual, but you can also run them more
interactively with [ReTest.jl](https://github.com/JuliaTesting/ReTest.jl) and
[TestEnv.jl](https://github.com/JuliaTesting/TestEnv.jl):
```julia-repl
julia> using TestEnv; TestEnv.activate(); includet("test/LibSSHTests.jl")
julia> LibSSHTests.runtests()
```

This is particularly helpful when developing since ReTest.jl allows filtering of
specific testsets to execute.

### Writing documentation

Here's a suggested workflow if you're writing documentation:
```julia-repl
pkg> activate docs
julia> using LiveServer
julia> servedocs(; include_dirs=["src"])
```

This will start a server with
[LiveServer.jl](https://github.com/tlienart/LiveServer.jl) to automatically
rebuild the docs when they're changed. But if you've done something like changed
a docstring and only want to build it once, this will work too:
```julia
pkg> activate docs
julia> include("docs/make.jl")
```

Note that the examples are generated from `test/examples.jl`, so to update that
you should edit `test/examples.jl` and re-run the tests (the `Examples` testset
in particular).
