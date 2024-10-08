import Revise
import Literate
import Changelog
import Documenter
import Documenter: Remotes, makedocs, deploydocs

import LibSSH

include("../doc_utils.jl")
import .DocUtils: read_tags, get_url


tags = read_tags()

"""
Helper function used by bindings.md to filter specific symbols.

The autogenerated bindings are documented by group. This will look up a symbol
and check if it's part of the given group or not.
"""
function group_filter(x, group)
    # Only allow constants in the GLOBAL group
    if x isa Integer
        return group == "GLOBAL"
    end

    name = nameof(x)
    name_str = string(name)
    prefixed_name = Symbol(startswith(name_str, "ssh_") ? name_str : "ssh_$(name_str)")

    # Autogenerated structs from Clang.jl start with '__', we ignore these
    if startswith(name_str, "__")
        return false
    end

    # If `group` is nothing that means we're looking for ungrouped symbols, so
    # we check whether the symbol is in the tags at all.
    if isnothing(group)
        return !haskey(tags, name) && !haskey(tags, prefixed_name)
    end

    # From here on we only consider grouped symbols
    if haskey(tags, name) || haskey(tags, prefixed_name)
        upstream_name = haskey(tags, name) ? name : prefixed_name

        anchorfile = tags[upstream_name][1]
        if group == "GLOBAL"
            return anchorfile == "group__libssh.html"
        else
            return contains(anchorfile, group)
        end
    else
        return false
    end
end

# Always trigger a revise to pick up the latest docstrings. This is useful when
# working with servedocs().
Revise.revise()

# Build the examples
Literate.markdown(joinpath(@__DIR__, "src/examples.jl"),
                  joinpath(@__DIR__, "src");
                  execute=true,
                  flavor=Literate.DocumenterFlavor())

# Build the changelog
Changelog.generate(
    Changelog.Documenter(),
    joinpath(@__DIR__, "src/changelog.md"),
    joinpath(@__DIR__, "src/generated_changelog.md"),
    repo="JuliaWeb/LibSSH.jl"
)

# Build and deploy the docs
makedocs(;
         repo = Remotes.GitHub("JuliaWeb", "LibSSH.jl"),
         sitename = "LibSSH",
         format = Documenter.HTML(
             prettyurls=get(ENV, "CI", "false") == "true",
             size_threshold_warn=500_000,
             size_threshold=600_000),
         pages = [
             "index.md",
             "Examples" => "examples.md",
             "sessions_and_channels.md",
             "sftp.md",
             "server_support.md",
             "utilities.md",
             "bindings.md",
             "generated_changelog.md",
             "contributing.md"
         ],
         modules = [LibSSH],
         warnonly = :missing_docs
         )
deploydocs(; repo="github.com/JuliaWeb/LibSSH.jl.git")
