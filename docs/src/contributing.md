# Contributing

Libssh is a fairly large project and most of the API still doesn't have
high-level wrappers in LibSSH.jl. For example:
- Reverse port forwarding
- Unix socket forwarding
- Complete SFTP/SCP support

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
# Note that we ignore automatically generated files, otherwise we'd end up in an
# infinite loop.
julia> servedocs(; include_dirs=["src"], skip_files=["docs/src/examples.md", "docs/src/generated_changelog.md"])
```

This will start a server with
[LiveServer.jl](https://github.com/tlienart/LiveServer.jl) to automatically
rebuild the docs when they're changed. But if you've done something like changed
a docstring and only want to build it once, this will work too:
```julia
pkg> activate docs
julia> include("docs/make.jl")
```

Note that the examples are generated automatically from `docs/src/examples.jl`.

### Updating the bindings

If there's a new upstream release of libssh, here's how to update everything:
1. Update the
   [`build_tarballs.jl`](https://github.com/JuliaPackaging/Yggdrasil/blob/master/L/libssh/build_tarballs.jl)
   script to build the new version, and submit a PR to Yggdrasil to update
   `libssh_jll`. When testing it's often useful to deploy it locally first:
   ```bash
   $ julia --project=@project-with-binary-builder build_tarballs.jl --deploy=local
   ```
1. Update the generated bindings:
   ```julia-repl
   pkg> activate gen
   julia> include("gen/gen.jl")
   ```

   If you've build and deployed `libssh_jll` locally make sure to `pkg> dev
   libssh_jll` first, or `] up` if the JLL has already been updated in
   Yggdrasil.
1. Run the tests to make sure everything works, then bump the LibSSH.jl version
   number and release \o/
