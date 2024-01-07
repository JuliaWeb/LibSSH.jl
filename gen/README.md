# libssh generator

To generate the bindings for libssh, run:
```julia
pkg> activate gen
julia> include("gen/gen.jl")
```

Make sure to `pkg> up` first if you're regenerating them for a new version of
libssh (assuming the JLL has already been updated).
