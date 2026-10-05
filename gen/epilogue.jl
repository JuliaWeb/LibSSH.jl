# Wrapped manually because the generated `socket_t(-1)` throws an InexactError
# on Windows, where socket_t is unsigned. The C definition is `((socket_t) -1)`,
# i.e. a cast that wraps around. This can't go in the prologue because socket_t
# isn't defined until later in the module.
const SSH_INVALID_SOCKET = -1 % socket_t

# Manually wrapped for now until this is merged:
# https://gitlab.com/libssh/libssh-mirror/-/merge_requests/538
function sftp_channel_default_data_callback(session, channel, data, len, is_stderr, userdata)
    @ccall libssh.sftp_channel_default_data_callback(session::ssh_session, channel::ssh_channel, data::Ptr{Cvoid}, len::UInt32, is_stderr::Cint, userdata::Ptr{Cvoid})::Cint
end
