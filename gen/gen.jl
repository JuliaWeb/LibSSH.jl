import libssh_jll

import XML
import MacroTools
import MacroTools: @capture
import Clang
import Clang.Generators: ExprNode, AbstractFunctionNodeType

include("../doc_utils.jl")
import .DocUtils: read_tags, get_url


ctx_objects = Dict{Symbol, Any}()

# These are lists of functions that we'll rewrite to return Julia types
string_functions = [:ssh_message_auth_user, :ssh_message_auth_password,
                    :ssh_userauth_kbdint_getname, :ssh_userauth_kbdint_getanswer,
                    :ssh_userauth_kbdint_getprompt]
bool_functions = [:ssh_message_auth_kbdint_is_response]
ssh_ok_functions = [:ssh_message_auth_reply_success, :ssh_message_auth_set_methods,
                    :ssh_message_reply_default,
                    :ssh_options_get, :ssh_options_set, :ssh_options_get_port]
all_rewritable_functions = vcat(string_functions, bool_functions, ssh_ok_functions)

"""
Helper function to generate documentation for symbols with missing docstrings.

For the most part we rely on the Doxygen tag file to generate a URL to the
upstream docs, except for certain structs/constants are referenced by the
function docs.
"""
function get_docs(node::ExprNode, doc::Vector{String})
    tags = ctx_objects[:tags]

    url = haskey(tags, node.id) ? get_url(node.id, ctx_objects[:tags]) : nothing

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
    elseif node.id == :ssh_message_auth_interactive_request
        String["Initiate keyboard-interactive authentication from a server."]

    # Internal Clang.jl structs start with '__' and we don't want to document them
    elseif startswith(string(node.id), "__")
        String[]

    elseif node.id in all_rewritable_functions
        symbol_ref = isempty(doc) && haskey(tags, node.id) ? "[`$(node.id)`]($url)" : "`$(node.id)`"
        original_docs_mention = isempty(doc) ? "" : " Original upstream documentation is below."
        autogen_line = String["Auto-generated wrapper around $symbol_ref.$original_docs_mention"]

        if isempty(doc)
            autogen_line
        else
            vcat(autogen_line,
                 "\n---\n",
                 doc)
        end

    # The generic case where we try to generate a link to the upstream docs
    elseif isempty(doc) && node.type isa AbstractFunctionNodeType && haskey(tags, node.id)
        String["[Upstream documentation]($url)."]
    else
        doc
    end
end

function rewrite!(ctx)
    dag = ctx.dag

    for node in dag.nodes
        for i in eachindex(node.exprs)
            expr = node.exprs[i]

            # Look for function expressions
            if @capture(expr, function name_(args__) body_ end)
                wrapper = nothing

                # Check if we can rewrite the function
                if name in string_functions
                    wrapper = quote
                        if ret == C_NULL
                            if throw
                                Base.throw(LibSSHException($("Error from $name, no string found (returned C_NULL)")))
                            else
                                return ret
                            end
                        end

                        return unsafe_string(Ptr{UInt8}(ret))
                    end
                elseif name in bool_functions
                    wrapper = :(return Bool(ret))
                elseif name in ssh_ok_functions
                    wrapper = quote
                        if ret != SSH_OK && throw
                            # This ugly concatenation is necessary because we
                            # have to interpolate the function name into the
                            # error string but also keep the return value
                            # interpolation from being escaped.
                            Base.throw(LibSSHException($("Error from $name, did not return SSH_OK: ") * "$(ret)"))
                        end

                        return ret
                    end
                end

                if !isnothing(wrapper)
                    new_expr = quote
                        function $name($(args...); throw=true)
                            ret = $body
                            $wrapper
                        end
                    end

                    # Note that the node retains the old ID, only the expression changed
                    node.exprs[i] = MacroTools.prettify(new_expr)
                end
            end
        end
    end
end

cd(@__DIR__) do
    # Load the doxygen tags
    ctx_objects[:tags] = read_tags()

    # Set the options
    options = Clang.load_options(joinpath(@__DIR__, "generator.toml"))
    options["general"]["callback_documentation"] = get_docs
    ctx_objects[:codegen_options] = options["codegen"]

    include_dir = normpath(libssh_jll.artifact_dir, "include")
    headers = [joinpath(include_dir, "libssh", name) for name in
               ["libssh.h", "libssh_version.h", "sftp.h", "server.h", "callbacks.h"]]
    args = Clang.get_default_args()
    push!(args, "-I$include_dir")

    # Generate the bindings
    ctx = Clang.create_context(headers, args, options)
    ctx_objects[:dag] = ctx.dag
    Clang.build!(ctx, Clang.BUILDSTAGE_NO_PRINTING)

    # Rewrite expressions
    rewrite!(ctx)

    Clang.build!(ctx, Clang.BUILDSTAGE_PRINTING_ONLY)

    empty!(ctx_objects)

    nothing
end
