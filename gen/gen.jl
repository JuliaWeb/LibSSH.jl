import libssh_jll

using MD5
import XML
import Clang
import Clang: LibClang, spelling
using Clang.Generators


ctx_objects = Dict{Symbol, Any}()

"""
Helper function to generate documentation for symbols with missing docstrings.

For the most part we rely on the Doxygen tag file to generate a URL to the
upstream docs, except for certain structs/constants are referenced by the
function docs.
"""
function get_docs(node::ExprNode)
    tags = ctx_objects[:tags]

    # There's a bunch of special cases that we take care of first, these are all
    # referenced by other docstrings and Documenter.jl will complain if they
    # don't have docstrings too.
    if node.id == :ssh_bind
        String["[Server struct](https://api.libssh.org/stable/group__libssh__server.html)"]
    elseif node.id == :SSH_PACKET_NOT_USED
        String["[Upstream documentation](https://api.libssh.org/stable/group__libssh__callbacks.html#ga4766917128a12b646a8aee7ebc019f8c)."]
    elseif node.id == :SSH_ERROR
        String["Value returned if an error occurred."]
    elseif node.id == :SSH_OK
        String["Value returned on success."]
    elseif node.id == :SSH_AGAIN
        String["Value returned when the function is in non-blocking mode and must be called again."]
    elseif node.id == :ssh_bind_callbacks
        String["Callbacks for a [`ssh_bind`](@ref) ([upstream documentation](https://api.libssh.org/stable/group__libssh__server.html))."]
    elseif startswith(string(node.id), "SSH_AUTH_METHOD")
        String["Auth method enum ([upstream documentation](https://api.libssh.org/stable/libssh_tutor_authentication.html))."]
    elseif node.id == :ssh_threads_callbacks_struct
        String["Threads callbacks. See [`ssh_threads_set_callbacks`](@ref)"]
    elseif node.id == :ssh_session
        String["Session struct ([upstream documentation](https://api.libssh.org/stable/libssh_tutor_guided_tour.html))."]

    # The generic case where we try to generate a link to the upstream docs
    elseif node.type isa AbstractFunctionNodeType && haskey(tags, node.id)
        anchorfile, anchor = ctx_objects[:tags][node.id]
        url = "https://api.libssh.org/stable/$(anchorfile)#$(anchor)"

        String["[Upstream documentation]($url)."]
    else
        String[]
    end
end

"""
Read the function info from a Doxygen tag file into a dict.

In particular, the anchor file and the anchor itself.
"""
function read_tags()
    doc = read(libssh_jll.doxygen_tags, XML.Node)

    tags = Dict{Symbol, Any}()
    main_element = XML.children(doc)[2]
    for compound in XML.children(main_element)
        if compound["kind"] == "group"
            for child in filter(!isnothing, XML.children(compound))
                attrs = XML.attributes(child)
                if !isnothing(attrs) && get(attrs, "kind", "") == "function"
                    func_children = XML.children(child)
                    name = XML.simplevalue(func_children[2])
                    anchorfile = XML.simplevalue(func_children[3])
                    anchor = XML.simplevalue(func_children[4])

                    tags[Symbol(name)] = (anchorfile, anchor)
                end
            end
        end
    end

    return tags
end

cd(@__DIR__) do
    # Load the doxygen tags
    ctx_objects[:tags] = read_tags()

    # Set the options
    options = load_options(joinpath(@__DIR__, "generator.toml"))
    options["general"]["callback_documentation"] = get_docs
    ctx_objects[:codegen_options] = options["codegen"]

    include_dir = normpath(libssh_jll.artifact_dir, "include")
    headers = [joinpath(include_dir, "libssh", name) for name in
               ["libssh.h", "libssh_version.h", "sftp.h", "server.h", "callbacks.h"]]
    args = get_default_args()
    push!(args, "-I$include_dir")

    # Generate the bindings
    ctx = create_context(headers, args, options)
    ctx_objects[:dag] = ctx.dag
    build!(ctx)

    empty!(ctx_objects)

    nothing
end
