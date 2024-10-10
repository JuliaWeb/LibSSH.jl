import libssh_jll

import XML
import MacroTools
import MacroTools: @capture
import Clang
import Clang.Generators: ExprNode, AbstractFunctionNodeType, FunctionProto

include("../doc_utils.jl")
import .DocUtils: read_tags, get_url


ctx_objects = Dict{Symbol, Any}()

# These are lists of functions that we'll rewrite to return Julia types
string_functions = [:ssh_message_auth_user, :ssh_message_auth_password,
                    :ssh_userauth_kbdint_getname, :ssh_userauth_kbdint_getanswer,
                    :ssh_userauth_kbdint_getprompt,
                    :sftp_extensions_get_name, :sftp_extensions_get_data]
bool_functions = [:ssh_message_auth_kbdint_is_response]
ssh_ok_functions = [:ssh_message_auth_reply_success, :ssh_message_auth_set_methods,
                    :ssh_message_reply_default,
                    :ssh_options_get, :ssh_options_set, :ssh_options_get_port]

# These functions require the ssh_session to be in blocking mode, so we always
# call them with @threadcall.
threadcall_functions = [:sftp_new, :sftp_init, :sftp_open, :sftp_close,
                        :sftp_home_directory, :sftp_stat,
                        :sftp_aio_wait_read, :sftp_aio_wait_write,
                        :sftp_opendir, :sftp_readdir, :sftp_closedir]
all_rewritable_functions = vcat(string_functions, bool_functions, ssh_ok_functions, threadcall_functions)

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
    elseif node.id == :sftp_limits_t
        String["Pointer to a [`sftp_limits_struct`](@ref)"]

    # Internal Clang.jl structs and helper functions from us start with '_' and
    # we don't want to document them.
    elseif startswith(string(node.id), "_")
        String[]

    elseif node.id in all_rewritable_functions
        symbol_ref = isempty(doc) && haskey(tags, node.id) ? "[`$(node.id)()`]($url)" : "`$(node.id)()`"
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

function rewrite_string_function(name, args, body)
    quote
        function $name($(args...); throw=true)
            ret = $body

            if ret == C_NULL
                if throw
                    Base.throw(LibSSHException($("Error from $name, no string found (returned C_NULL)")))
                else
                    return ret
                end
            end

            return unsafe_string(Ptr{UInt8}(ret))
        end
    end
end

function rewrite_bool_function(name, args, body)
    quote
        function $name($(args...))
            ret = $body
            return Bool(ret)
        end
    end
end

function rewrite_ssh_ok_function(name, args, body)
    quote
        function $name($(args...); throw=true)
            ret = $body

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
end

"""
Rewrites a blocking libssh function into one that uses @threadcall. Some parts
of the libssh API don't support the non-blocking API, so to avoid these calls
blocking a whole thread we call them with @threadcall.

The problem is that @threadcall will not mark the calling region as GC safe,
which means that if the @threadcall returning depends on some other Julia code
executing (i.e. with the DemoServer) we'll likely deadlock when the other Julia
code tries to allocate and hits the GC.

To get around this we rewrite the original wrapper to call a @cfunction that
will create a safe region around the @ccall. In some future Julia release this
will be unnecessary and we'll be able to directly @threadcall blocking
functions: https://github.com/JuliaLang/julia/pull/55956
"""
function rewrite_threadcall_function!(dag, node, name, args, body)
    if !@capture(body, @ccall ccall_func_(ccall_args__)::ccall_ret_)
        error("Couldn't parse @ccall expr")
    end

    # We require the exact argument types to be passed because @ccall's
    # automatic type conversion may allocate. It's easier to just require the
    # user to do the right thing.
    arg_types = [expr.args[2] for expr in ccall_args]

    cfunc_name = Symbol(:_threadcall_, name)
    cfunc_expr = quote
        function $cfunc_name($(ccall_args...))
            gc_state = @ccall jl_gc_safe_enter()::Int8
            ret = $body
            @ccall jl_gc_safe_leave(gc_state::Int8)::Cvoid

            return ret
        end
    end
    cfunc_expr = MacroTools.prettify(cfunc_expr)

    new_node = ExprNode(cfunc_name, FunctionProto(), node.cursor, [cfunc_expr], Int[])

    wrapper = quote
        function $name($(ccall_args...))
            cfunc = @cfunction($cfunc_name, $ccall_ret, ($(arg_types...),))
            return @threadcall(cfunc, $ccall_ret, ($(arg_types...),), $(args...))
        end
    end

    return wrapper, new_node
end

function rewrite!(ctx)
    dag = ctx.dag

    nodes_to_insert = []
    for node_idx in eachindex(dag.nodes)
        node = dag.nodes[node_idx]

        for i in eachindex(node.exprs)
            expr = node.exprs[i]

            # Look for function expressions
            if @capture(expr, function name_(args__) body_ end)
                wrapper = nothing
                name_str = string(name)

                # Check if we can rewrite the function
                if name in string_functions
                    wrapper = rewrite_string_function(name, args, body)
                elseif name in bool_functions
                    wrapper = rewrite_bool_function(name, args, body)
                elseif name in ssh_ok_functions
                    wrapper = rewrite_ssh_ok_function(name, args, body)
                elseif name in threadcall_functions
                    wrapper, new_node = rewrite_threadcall_function!(dag, node, name, args, body)

                    push!(nodes_to_insert, (node_idx, new_node))
                end

                if !isnothing(wrapper)
                    # Note that the node retains the old ID, only the expression changed
                    node.exprs[i] = MacroTools.prettify(wrapper)
                end
            end
        end
    end

    # Iterate over the nodes to insert in reverse so we don't invalidate their
    # indices.
    for (idx, node) in reverse(nodes_to_insert)
        insert!(dag.nodes, idx, node)
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
    push!(args, "-I$include_dir", "-DWITH_SERVER=1")

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
