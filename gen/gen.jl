using libssh_jll
using Clang.Generators

cd(@__DIR__) do
    include_dir = normpath(libssh_jll.artifact_dir, "include")
    headers = [joinpath(include_dir, "libssh", name) for name in
               ["libssh.h", "libssh_version.h", "sftp.h", "server.h", "callbacks.h"]]
    options = load_options(joinpath(@__DIR__, "generator.toml"))
    args = get_default_args()
    push!(args, "-I$include_dir")

    ctx = create_context(headers, args, options)
    build!(ctx)
end
