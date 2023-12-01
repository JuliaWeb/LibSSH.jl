"""
$(TYPEDSIGNATURES)

Manual copy of the upstream macro.
"""
function ssh_callbacks_init(callbacks::Union{ssh_callbacks_struct, ssh_bind_callbacks_struct,
                                             ssh_server_callbacks_struct, ssh_channel_callbacks_struct})
    callbacks.size = sizeof(typeof(callbacks))
end
