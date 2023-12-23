using libssh_jll

using MD5
import Clang
import Clang: LibClang, spelling
using Clang.Generators
import Clang.Generators as gen


ctx_objects = Dict{Symbol, Any}()

function get_doxygen_group(func_name, filename)
    check = Base.Fix1(startswith, func_name)
    misc_functions = [
        "ssh_getpass",
        "ssh_dir_writeable",
        "ssh_get_hexa",
        "ssh_print_hexa",
        "ssh_log_hexdump",
        "ssh_version",
        "ssh_list_count",
        "ssh_dirname",
        "ssh_basename",
        "ssh_mkdir",
        "ssh_mkdirs",
        "ssh_path_expand_tilde",
        "ssh_timeout_update"
    ]
    message_functions = [
        "ssh_message_get",
        "ssh_message_type",
        "ssh_message_subtype",
        "ssh_message_free"
    ]

    if filename == "server.h"
        return "libssh__server"
    elseif filename == "sftp.h"
        return "libssh__sftp"
    end

    if func_name in ["ssh_init", "ssh_finalize"]
        "libssh"
    elseif func_name in misc_functions
        "libssh__misc"
    elseif func_name in message_functions
        "libssh__messages"
    elseif check("ssh_callbacks")
        "libssh__callbacks"
    elseif check("ssh_userauth")
        "libssh__auth"
    elseif check("ssh_buffer")
        "libssh__buffer"
    elseif check("ssh_channel")
        "libssh__channel"
    elseif check("ssh_get_error")
        "libssh__error"
    elseif check("ssh_set_log") || check("ssh_get_log")
        "libssh__log"
    elseif check("ssh_pki") || check("ssh_key")
        "libssh__pki"
    elseif check("ssh_poll") || check("ssh_event")
        "libssh__poll"
    elseif check("ssh_scp")
        "libssh__scp"
    elseif check("ssh_string")
        "libssh__string"
    elseif check("ssh_threads")
        "libssh__threads"
    else
        # The session group has names with a bunch of different prefixes, so
        # it's our fallback.
        "libssh__session"
    end
end

"""
Helper function to generate documentation for symbols with missing docstrings.

So here's the thing: we want to generate documentation for the bindings. Now
Clang.jl is pretty good at pulling docstrings from headers already, but many
docstrings in libssh are in the source files rather than the headers, so we
can't access them. Hence this callback function which is called by Clang.jl for
each node that it can't find docs for.

The hard part is generating a link to the upstream documentation. libssh uses
Doxygen, which creates stable links for symbols from an MD5 hash of their
signature. Doxygen does have a tag feature which creates an XML file with the
anchors but libssh doesn't use that, and of course waiting for the documentation
to be updated is too slow for our galaxy brain. Instead we recreate the
signature that Doxygen uses and hash it ourselves to generate the link. Which is
surprisingly reliable.
"""
function get_docs(node::ExprNode)
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
    elseif node.type isa AbstractFunctionNodeType
        # Get raw source code
        source = Clang.getSourceCode(node.cursor)

        # Don't bother documenting deprecating functions
        if occursin("SSH_DEPRECATED", source)
            return String["Deprecated function."]
        end

        # Remove leading macro
        source = strip(chopprefix(strip(source), "LIBSSH_API"))
        # Normalize to remove newlines and extraneous whitespace
        source = replace(source, '\n' => ' ')
        source = replace(source, r"\s{2,}" => ' ')

        # Find the start of the argument list
        args_start = findfirst('(', source)
        # Find the end of the function name. We do a search to ignore any
        # whitespace between the name and parenthesis like in 'int foo ()'.
        name_end = findprev(!isspace, source, args_start - 1)
        # Note the special case for '*' to handle signatures like 'void *foo()'
        name_start = findprev(x -> isspace(x) || x == '*', source, name_end) + 1
        func_name = source[name_start:name_end]

        # Find the return type, and replace types of the form 'void *name' with
        # 'void* name' (because that's what doxygen does).
        ret_str = replace(source[1:name_end], " *" => "* ")

        # Generate the signature that doxygen uses to generate its links:
        #     $ret $name$name($args)
        # See: https://github.com/doxygen/doxygen/blob/master/src/memberdef.cpp#L4249
        # And: https://stackoverflow.com/a/14243458
        signature = ret_str * func_name * source[args_start:end]

        # Get the file that the node was defined in
        location = Clang.getCursorLocation(node.cursor)
        cxfile_ptr = Ref{Ptr{Nothing}}()
        LibClang.clang_getFileLocation(location, cxfile_ptr, C_NULL, C_NULL, C_NULL)
        file_cxstring = LibClang.clang_getFileName(cxfile_ptr[])
        file_cstr = LibClang.clang_getCString(file_cxstring)
        file_path = unsafe_string(file_cstr)
        LibClang.clang_disposeString(file_cxstring)
        filename = basename(file_path)

        # Generate the final URL
        hash = bytes2hex(md5(signature))
        group = get_doxygen_group(func_name, filename)
        url = "https://api.libssh.org/stable/group__$(group).html#ga$(hash)"

        String["[Upstream documentation]($url)."]
    else
        String[]
    end
end

cd(@__DIR__) do
    options = load_options(joinpath(@__DIR__, "generator.toml"))
    options["general"]["callback_documentation"] = get_docs
    ctx_objects[:codegen_options] = options["codegen"]

    include_dir = normpath(libssh_jll.artifact_dir, "include")
    headers = [joinpath(include_dir, "libssh", name) for name in
               ["libssh.h", "libssh_version.h", "sftp.h", "server.h", "callbacks.h"]]
    args = get_default_args()
    push!(args, "-I$include_dir")

    ctx = create_context(headers, args, options)
    ctx_objects[:dag] = ctx.dag
    build!(ctx)

    empty!(ctx_objects)

    nothing
end
