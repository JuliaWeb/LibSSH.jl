"""
$(TYPEDSIGNATURES)

Get the type of a message. Wrapper around [`lib.ssh_message_type()`](@ref).
"""
function message_type(message::lib.ssh_message)
    ret = lib.ssh_message_type(message)
    if ret == SSH_ERROR
        throw(LibSSHException("Error when retrieving message type from message"))
    end

    return RequestType(ret)
end

"""
$(TYPEDSIGNATURES)

Get the subtype of a message. Wrapper around [`lib.ssh_message_subtype()`](@ref).
"""
function message_subtype(message::lib.ssh_message)
    ret = lib.ssh_message_subtype(message)
    if ret == SSH_ERROR
        throw(LibSSHException("Error when retrieving message subtype from message"))
    end

    return ret
end

"""
$(TYPEDSIGNATURES)

This is useful when writing a server, it will specify the requirements for
keyboard-interactive authentication to the client.

## Parameters

- `msg`: The message to reply to.
- `name`: The name of the message block.
- `instruction`: The instruction for the user.
- `prompts`: The prompts to show to the user.
- `echo`: Whether the client should echo the answer to the prompts (e.g. it
  probably shouldn't echo the password).

Wrapper around [`lib.ssh_message_auth_interactive_request()`](@ref).
"""
function message_auth_interactive_request(msg::lib.ssh_message,
                                          name::AbstractString, instruction::AbstractString,
                                          prompts::Vector{String}, echo::Vector{Bool})
    # Check that prompts and echo have the same length
    if length(prompts) != length(echo)
        throw(ArgumentError("`prompts` and `echo` must have the same length! Actual lengths are $(length(prompts)) and $(length(echo))"))
    end

    # Convert arguments to C types
    name_cstr = Base.cconvert(Cstring, name)
    instruction_cstr = Base.cconvert(Cstring, instruction)
    prompts_cstrs = [Base.cconvert(Cstring, p) for p in prompts]
    echo_arr = map(Cchar, echo)

    # Call library
    GC.@preserve prompts_cstrs echo_arr begin
        prompts_arr = pointer.(prompts_cstrs)

        ret = lib.ssh_message_auth_interactive_request(msg, name_cstr, instruction_cstr,
                                                       length(prompts), Ptr{Ptr{UInt8}}(pointer(prompts_arr)),
                                                       pointer(echo_arr))
    end

    if ret == SSH_ERROR
        throw(LibSSHException("Error when responding to kbdint auth request: $(ret)"))
    end

    return ret
end
