"""
$(TYPEDSIGNATURES)

Manual copy of the upstream macro.
"""
function ssh_callbacks_init(callbacks::Union{ssh_callbacks_struct, ssh_bind_callbacks_struct,
                                             ssh_server_callbacks_struct, ssh_channel_callbacks_struct})
    callbacks.size = sizeof(typeof(callbacks))
end

# Manually wrapped for now until this is merged:
# https://gitlab.com/libssh/libssh-mirror/-/merge_requests/538
function sftp_channel_default_data_callback(session, channel, data, len, is_stderr, userdata)
    @ccall libssh.sftp_channel_default_data_callback(session::ssh_session, channel::ssh_channel, data::Ptr{Cvoid}, len::UInt32, is_stderr::Cint, userdata::Ptr{Cvoid})::Cint
end
