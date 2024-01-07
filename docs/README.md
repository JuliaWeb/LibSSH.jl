# LibSSH.jl documentation

Here's a suggested workflow if you're writing documentation:
```julia-repl
pkg> activate docs
julia> using LiveServer
julia> servedocs(; include_dirs=["src"])
```

This will start a server with LiveServer.jl to automatically rebuild the docs
when they're changed. But if you've done something like changed a docstring and
only want to build it once, this will work too:
```julia
pkg> activate docs
julia> include("docs/make.jl")
```


