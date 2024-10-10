module lib

using CEnum: CEnum, @cenum

using libssh_jll
using DocStringExtensions

"""
$(TYPEDEF)

A custom exception type to represent errors from libssh's C API.
"""
struct LibSSHException <: Exception
    msg::String
end


const __uid_t = Cuint

const __gid_t = Cuint

const __mode_t = Cuint

const gid_t = __gid_t

const uid_t = __uid_t

const mode_t = __mode_t

const __fd_mask = Clong

mutable struct fd_set
    __fds_bits::NTuple{16, __fd_mask}
end

const socket_t = Cint

mutable struct ssh_channel_struct end

const ssh_channel = Ptr{ssh_channel_struct}

"""
    ssh_channel_free(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gad1417f9eae8928fed20faafe2d9dbfff).
"""
function ssh_channel_free(channel)
    @ccall libssh.ssh_channel_free(channel::ssh_channel)::Cvoid
end

mutable struct ssh_key_struct end

const ssh_key = Ptr{ssh_key_struct}

mutable struct ssh_knownhosts_entry
    hostname::Ptr{Cchar}
    unparsed::Ptr{Cchar}
    publickey::ssh_key
    comment::Ptr{Cchar}
end

"""
    ssh_knownhosts_entry_free(entry)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga97b827bd9eef76277e8420359e843cd8).
"""
function ssh_knownhosts_entry_free(entry)
    @ccall libssh.ssh_knownhosts_entry_free(entry::Ptr{ssh_knownhosts_entry})::Cvoid
end

mutable struct ssh_message_struct end

const ssh_message = Ptr{ssh_message_struct}

"""
    ssh_message_free(msg)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__messages.html#ga9d1b1d2279c6be3539f2b630960759c3).
"""
function ssh_message_free(msg)
    @ccall libssh.ssh_message_free(msg::ssh_message)::Cvoid
end

"""
    ssh_key_free(key)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga08808beb83a42ccd6f1c710ddeb1b4c2).
"""
function ssh_key_free(key)
    @ccall libssh.ssh_key_free(key::ssh_key)::Cvoid
end

mutable struct ssh_string_struct end

const ssh_string = Ptr{ssh_string_struct}

"""
    ssh_string_free(str)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__string.html#gacd9c4eb69f7ecfdcf709deb8dde6a5a8).
"""
function ssh_string_free(str)
    @ccall libssh.ssh_string_free(str::ssh_string)::Cvoid
end

"""
    ssh_string_free_char(s)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__string.html#gafc10700722d6cafc468c2ee97585449a).
"""
function ssh_string_free_char(s)
    @ccall libssh.ssh_string_free_char(s::Ptr{Cchar})::Cvoid
end

mutable struct ssh_buffer_struct end

const ssh_buffer = Ptr{ssh_buffer_struct}

"""
    ssh_buffer_free(buffer)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__buffer.html#ga608cf73226454f21e8b2f9f1d838c5fc).
"""
function ssh_buffer_free(buffer)
    @ccall libssh.ssh_buffer_free(buffer::ssh_buffer)::Cvoid
end

mutable struct ssh_counter_struct
    in_bytes::UInt64
    out_bytes::UInt64
    in_packets::UInt64
    out_packets::UInt64
end

const ssh_counter = Ptr{ssh_counter_struct}

mutable struct ssh_agent_struct end

const ssh_agent = Ptr{ssh_agent_struct}

mutable struct ssh_pcap_file_struct end

const ssh_pcap_file = Ptr{ssh_pcap_file_struct}

mutable struct ssh_scp_struct end

const ssh_scp = Ptr{ssh_scp_struct}

mutable struct ssh_session_struct end

"""
Session struct ([upstream documentation](https://api.libssh.org/stable/libssh_tutor_guided_tour.html)).
"""
const ssh_session = Ptr{ssh_session_struct}

mutable struct ssh_event_struct end

const ssh_event = Ptr{ssh_event_struct}

mutable struct ssh_connector_struct end

const ssh_connector = Ptr{ssh_connector_struct}

const ssh_gssapi_creds = Ptr{Cvoid}

@cenum ssh_kex_types_e::UInt32 begin
    SSH_KEX = 0
    SSH_HOSTKEYS = 1
    SSH_CRYPT_C_S = 2
    SSH_CRYPT_S_C = 3
    SSH_MAC_C_S = 4
    SSH_MAC_S_C = 5
    SSH_COMP_C_S = 6
    SSH_COMP_S_C = 7
    SSH_LANG_C_S = 8
    SSH_LANG_S_C = 9
end

@cenum ssh_auth_e::Int32 begin
    SSH_AUTH_SUCCESS = 0
    SSH_AUTH_DENIED = 1
    SSH_AUTH_PARTIAL = 2
    SSH_AUTH_INFO = 3
    SSH_AUTH_AGAIN = 4
    SSH_AUTH_ERROR = -1
end

@cenum ssh_requests_e::UInt32 begin
    SSH_REQUEST_AUTH = 1
    SSH_REQUEST_CHANNEL_OPEN = 2
    SSH_REQUEST_CHANNEL = 3
    SSH_REQUEST_SERVICE = 4
    SSH_REQUEST_GLOBAL = 5
end

@cenum ssh_channel_type_e::UInt32 begin
    SSH_CHANNEL_UNKNOWN = 0
    SSH_CHANNEL_SESSION = 1
    SSH_CHANNEL_DIRECT_TCPIP = 2
    SSH_CHANNEL_FORWARDED_TCPIP = 3
    SSH_CHANNEL_X11 = 4
    SSH_CHANNEL_AUTH_AGENT = 5
end

@cenum ssh_channel_requests_e::UInt32 begin
    SSH_CHANNEL_REQUEST_UNKNOWN = 0
    SSH_CHANNEL_REQUEST_PTY = 1
    SSH_CHANNEL_REQUEST_EXEC = 2
    SSH_CHANNEL_REQUEST_SHELL = 3
    SSH_CHANNEL_REQUEST_ENV = 4
    SSH_CHANNEL_REQUEST_SUBSYSTEM = 5
    SSH_CHANNEL_REQUEST_WINDOW_CHANGE = 6
    SSH_CHANNEL_REQUEST_X11 = 7
end

@cenum ssh_global_requests_e::UInt32 begin
    SSH_GLOBAL_REQUEST_UNKNOWN = 0
    SSH_GLOBAL_REQUEST_TCPIP_FORWARD = 1
    SSH_GLOBAL_REQUEST_CANCEL_TCPIP_FORWARD = 2
    SSH_GLOBAL_REQUEST_KEEPALIVE = 3
    SSH_GLOBAL_REQUEST_NO_MORE_SESSIONS = 4
end

@cenum ssh_publickey_state_e::Int32 begin
    SSH_PUBLICKEY_STATE_ERROR = -1
    SSH_PUBLICKEY_STATE_NONE = 0
    SSH_PUBLICKEY_STATE_VALID = 1
    SSH_PUBLICKEY_STATE_WRONG = 2
end

@cenum ssh_server_known_e::Int32 begin
    SSH_SERVER_ERROR = -1
    SSH_SERVER_NOT_KNOWN = 0
    SSH_SERVER_KNOWN_OK = 1
    SSH_SERVER_KNOWN_CHANGED = 2
    SSH_SERVER_FOUND_OTHER = 3
    SSH_SERVER_FILE_NOT_FOUND = 4
end

@cenum ssh_known_hosts_e::Int32 begin
    SSH_KNOWN_HOSTS_ERROR = -2
    SSH_KNOWN_HOSTS_NOT_FOUND = -1
    SSH_KNOWN_HOSTS_UNKNOWN = 0
    SSH_KNOWN_HOSTS_OK = 1
    SSH_KNOWN_HOSTS_CHANGED = 2
    SSH_KNOWN_HOSTS_OTHER = 3
end

@cenum ssh_error_types_e::UInt32 begin
    SSH_NO_ERROR = 0
    SSH_REQUEST_DENIED = 1
    SSH_FATAL = 2
    SSH_EINTR = 3
end

@cenum ssh_keytypes_e::UInt32 begin
    SSH_KEYTYPE_UNKNOWN = 0
    SSH_KEYTYPE_DSS = 1
    SSH_KEYTYPE_RSA = 2
    SSH_KEYTYPE_RSA1 = 3
    SSH_KEYTYPE_ECDSA = 4
    SSH_KEYTYPE_ED25519 = 5
    SSH_KEYTYPE_DSS_CERT01 = 6
    SSH_KEYTYPE_RSA_CERT01 = 7
    SSH_KEYTYPE_ECDSA_P256 = 8
    SSH_KEYTYPE_ECDSA_P384 = 9
    SSH_KEYTYPE_ECDSA_P521 = 10
    SSH_KEYTYPE_ECDSA_P256_CERT01 = 11
    SSH_KEYTYPE_ECDSA_P384_CERT01 = 12
    SSH_KEYTYPE_ECDSA_P521_CERT01 = 13
    SSH_KEYTYPE_ED25519_CERT01 = 14
    SSH_KEYTYPE_SK_ECDSA = 15
    SSH_KEYTYPE_SK_ECDSA_CERT01 = 16
    SSH_KEYTYPE_SK_ED25519 = 17
    SSH_KEYTYPE_SK_ED25519_CERT01 = 18
end

@cenum ssh_keycmp_e::UInt32 begin
    SSH_KEY_CMP_PUBLIC = 0
    SSH_KEY_CMP_PRIVATE = 1
    SSH_KEY_CMP_CERTIFICATE = 2
end

@cenum __JL_Ctag_9::UInt32 begin
    SSH_LOG_NOLOG = 0
    SSH_LOG_WARNING = 1
    SSH_LOG_PROTOCOL = 2
    SSH_LOG_PACKET = 3
    SSH_LOG_FUNCTIONS = 4
end

"""
    ssh_control_master_options_e

@}
"""
@cenum ssh_control_master_options_e::UInt32 begin
    SSH_CONTROL_MASTER_NO = 0
    SSH_CONTROL_MASTER_AUTO = 1
    SSH_CONTROL_MASTER_YES = 2
    SSH_CONTROL_MASTER_ASK = 3
    SSH_CONTROL_MASTER_AUTOASK = 4
end

@cenum ssh_options_e::UInt32 begin
    SSH_OPTIONS_HOST = 0
    SSH_OPTIONS_PORT = 1
    SSH_OPTIONS_PORT_STR = 2
    SSH_OPTIONS_FD = 3
    SSH_OPTIONS_USER = 4
    SSH_OPTIONS_SSH_DIR = 5
    SSH_OPTIONS_IDENTITY = 6
    SSH_OPTIONS_ADD_IDENTITY = 7
    SSH_OPTIONS_KNOWNHOSTS = 8
    SSH_OPTIONS_TIMEOUT = 9
    SSH_OPTIONS_TIMEOUT_USEC = 10
    SSH_OPTIONS_SSH1 = 11
    SSH_OPTIONS_SSH2 = 12
    SSH_OPTIONS_LOG_VERBOSITY = 13
    SSH_OPTIONS_LOG_VERBOSITY_STR = 14
    SSH_OPTIONS_CIPHERS_C_S = 15
    SSH_OPTIONS_CIPHERS_S_C = 16
    SSH_OPTIONS_COMPRESSION_C_S = 17
    SSH_OPTIONS_COMPRESSION_S_C = 18
    SSH_OPTIONS_PROXYCOMMAND = 19
    SSH_OPTIONS_BINDADDR = 20
    SSH_OPTIONS_STRICTHOSTKEYCHECK = 21
    SSH_OPTIONS_COMPRESSION = 22
    SSH_OPTIONS_COMPRESSION_LEVEL = 23
    SSH_OPTIONS_KEY_EXCHANGE = 24
    SSH_OPTIONS_HOSTKEYS = 25
    SSH_OPTIONS_GSSAPI_SERVER_IDENTITY = 26
    SSH_OPTIONS_GSSAPI_CLIENT_IDENTITY = 27
    SSH_OPTIONS_GSSAPI_DELEGATE_CREDENTIALS = 28
    SSH_OPTIONS_HMAC_C_S = 29
    SSH_OPTIONS_HMAC_S_C = 30
    SSH_OPTIONS_PASSWORD_AUTH = 31
    SSH_OPTIONS_PUBKEY_AUTH = 32
    SSH_OPTIONS_KBDINT_AUTH = 33
    SSH_OPTIONS_GSSAPI_AUTH = 34
    SSH_OPTIONS_GLOBAL_KNOWNHOSTS = 35
    SSH_OPTIONS_NODELAY = 36
    SSH_OPTIONS_PUBLICKEY_ACCEPTED_TYPES = 37
    SSH_OPTIONS_PROCESS_CONFIG = 38
    SSH_OPTIONS_REKEY_DATA = 39
    SSH_OPTIONS_REKEY_TIME = 40
    SSH_OPTIONS_RSA_MIN_SIZE = 41
    SSH_OPTIONS_IDENTITY_AGENT = 42
    SSH_OPTIONS_IDENTITIES_ONLY = 43
    SSH_OPTIONS_CONTROL_MASTER = 44
    SSH_OPTIONS_CONTROL_PATH = 45
    SSH_OPTIONS_CERTIFICATE = 46
    SSH_OPTIONS_PROXYJUMP = 47
    SSH_OPTIONS_PROXYJUMP_CB_LIST_APPEND = 48
end

@cenum __JL_Ctag_10::UInt32 begin
    SSH_SCP_WRITE = 0
    SSH_SCP_READ = 1
    SSH_SCP_RECURSIVE = 16
end

@cenum ssh_scp_request_types::UInt32 begin
    SSH_SCP_REQUEST_NEWDIR = 1
    SSH_SCP_REQUEST_NEWFILE = 2
    SSH_SCP_REQUEST_EOF = 3
    SSH_SCP_REQUEST_ENDDIR = 4
    SSH_SCP_REQUEST_WARNING = 5
end

@cenum ssh_connector_flags_e::UInt32 begin
    SSH_CONNECTOR_STDOUT = 1
    SSH_CONNECTOR_STDINOUT = 1
    SSH_CONNECTOR_STDERR = 2
    SSH_CONNECTOR_BOTH = 3
end

"""
    ssh_blocking_flush(session, timeout)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga60da8e2c47897a209a455923c35d52d8).
"""
function ssh_blocking_flush(session, timeout)
    @ccall libssh.ssh_blocking_flush(session::ssh_session, timeout::Cint)::Cint
end

"""
    ssh_channel_accept_x11(channel, timeout_ms)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga548bd0f77a50b7c8180942544b375866).
"""
function ssh_channel_accept_x11(channel, timeout_ms)
    @ccall libssh.ssh_channel_accept_x11(channel::ssh_channel, timeout_ms::Cint)::ssh_channel
end

"""
    ssh_channel_change_pty_size(channel, cols, rows)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gaf5d55c90f3d98c583df23d21905c1127).
"""
function ssh_channel_change_pty_size(channel, cols, rows)
    @ccall libssh.ssh_channel_change_pty_size(channel::ssh_channel, cols::Cint, rows::Cint)::Cint
end

"""
    ssh_channel_close(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga238f07e0455456a5bfd8a49ead917732).
"""
function ssh_channel_close(channel)
    @ccall libssh.ssh_channel_close(channel::ssh_channel)::Cint
end

"""
    ssh_channel_get_exit_state(channel, pexit_code, pexit_signal, pcore_dumped)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga17b249b4abd204fc776a902bddc14c01).
"""
function ssh_channel_get_exit_state(channel, pexit_code, pexit_signal, pcore_dumped)
    @ccall libssh.ssh_channel_get_exit_state(channel::ssh_channel, pexit_code::Ptr{UInt32}, pexit_signal::Ptr{Ptr{Cchar}}, pcore_dumped::Ptr{Cint})::Cint
end

"""
    ssh_channel_get_exit_status(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga9eea019dd0bbaa8a817fff2c762d1a2d).
"""
function ssh_channel_get_exit_status(channel)
    @ccall libssh.ssh_channel_get_exit_status(channel::ssh_channel)::Cint
end

"""
    ssh_channel_get_session(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga747aa5315575aa7ac9d8367c7372d8dd).
"""
function ssh_channel_get_session(channel)
    @ccall libssh.ssh_channel_get_session(channel::ssh_channel)::ssh_session
end

"""
    ssh_channel_is_closed(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gab2720b44cb7f1dfe2b38ffe07c2f45c7).
"""
function ssh_channel_is_closed(channel)
    @ccall libssh.ssh_channel_is_closed(channel::ssh_channel)::Cint
end

"""
    ssh_channel_is_eof(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gab535264029443d77214c0615a0788b0a).
"""
function ssh_channel_is_eof(channel)
    @ccall libssh.ssh_channel_is_eof(channel::ssh_channel)::Cint
end

"""
    ssh_channel_is_open(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gaaafcda943c96ddb91e5c28c0bdee7045).
"""
function ssh_channel_is_open(channel)
    @ccall libssh.ssh_channel_is_open(channel::ssh_channel)::Cint
end

"""
    ssh_channel_new(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gada8ccda7bf65165fe145d3096a252dcc).
"""
function ssh_channel_new(session)
    @ccall libssh.ssh_channel_new(session::ssh_session)::ssh_channel
end

"""
    ssh_channel_open_auth_agent(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga6c4d4f5436dd5be58973606c6bcd8bb4).
"""
function ssh_channel_open_auth_agent(channel)
    @ccall libssh.ssh_channel_open_auth_agent(channel::ssh_channel)::Cint
end

"""
    ssh_channel_open_forward(channel, remotehost, remoteport, sourcehost, localport)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gae86b0704a1f2bdebb268b55567f7f47b).
"""
function ssh_channel_open_forward(channel, remotehost, remoteport, sourcehost, localport)
    @ccall libssh.ssh_channel_open_forward(channel::ssh_channel, remotehost::Ptr{Cchar}, remoteport::Cint, sourcehost::Ptr{Cchar}, localport::Cint)::Cint
end

"""
    ssh_channel_open_forward_unix(channel, remotepath, sourcehost, localport)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga93ddd5055eb3322d38c70986aa63c673).
"""
function ssh_channel_open_forward_unix(channel, remotepath, sourcehost, localport)
    @ccall libssh.ssh_channel_open_forward_unix(channel::ssh_channel, remotepath::Ptr{Cchar}, sourcehost::Ptr{Cchar}, localport::Cint)::Cint
end

"""
    ssh_channel_open_session(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gaf051dd30d75bf6dc45d1a5088cf970bd).
"""
function ssh_channel_open_session(channel)
    @ccall libssh.ssh_channel_open_session(channel::ssh_channel)::Cint
end

"""
    ssh_channel_open_x11(channel, orig_addr, orig_port)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gae4aa2cb2a96cfe13712150517d6a90da).
"""
function ssh_channel_open_x11(channel, orig_addr, orig_port)
    @ccall libssh.ssh_channel_open_x11(channel::ssh_channel, orig_addr::Ptr{Cchar}, orig_port::Cint)::Cint
end

"""
    ssh_channel_poll(channel, is_stderr)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga157f7d1df5de07ec6c6976e2034ba6e2).
"""
function ssh_channel_poll(channel, is_stderr)
    @ccall libssh.ssh_channel_poll(channel::ssh_channel, is_stderr::Cint)::Cint
end

"""
    ssh_channel_poll_timeout(channel, timeout, is_stderr)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gab56c7b7959e4c23959f2989468811661).
"""
function ssh_channel_poll_timeout(channel, timeout, is_stderr)
    @ccall libssh.ssh_channel_poll_timeout(channel::ssh_channel, timeout::Cint, is_stderr::Cint)::Cint
end

"""
    ssh_channel_read(channel, dest, count, is_stderr)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gac92381c4c5d4a7eab35f6e84686f033d).
"""
function ssh_channel_read(channel, dest, count, is_stderr)
    @ccall libssh.ssh_channel_read(channel::ssh_channel, dest::Ptr{Cvoid}, count::UInt32, is_stderr::Cint)::Cint
end

"""
    ssh_channel_read_timeout(channel, dest, count, is_stderr, timeout_ms)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga2f4e02cb3b3adbc30a534623164068fd).
"""
function ssh_channel_read_timeout(channel, dest, count, is_stderr, timeout_ms)
    @ccall libssh.ssh_channel_read_timeout(channel::ssh_channel, dest::Ptr{Cvoid}, count::UInt32, is_stderr::Cint, timeout_ms::Cint)::Cint
end

"""
    ssh_channel_read_nonblocking(channel, dest, count, is_stderr)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gaaca5a3fbe9839c3ffb37b746afc35f4c).
"""
function ssh_channel_read_nonblocking(channel, dest, count, is_stderr)
    @ccall libssh.ssh_channel_read_nonblocking(channel::ssh_channel, dest::Ptr{Cvoid}, count::UInt32, is_stderr::Cint)::Cint
end

"""
    ssh_channel_request_env(channel, name, value)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga7aede2f9af4c494ff9e41fc08a4572f1).
"""
function ssh_channel_request_env(channel, name, value)
    @ccall libssh.ssh_channel_request_env(channel::ssh_channel, name::Ptr{Cchar}, value::Ptr{Cchar})::Cint
end

"""
    ssh_channel_request_exec(channel, cmd)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga567d509183ade0a77190f390e2b5747d).
"""
function ssh_channel_request_exec(channel, cmd)
    @ccall libssh.ssh_channel_request_exec(channel::ssh_channel, cmd::Ptr{Cchar})::Cint
end

"""
    ssh_channel_request_pty(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga37c1cec33fe5a2f184768aba52e3a0db).
"""
function ssh_channel_request_pty(channel)
    @ccall libssh.ssh_channel_request_pty(channel::ssh_channel)::Cint
end

function ssh_channel_request_pty_size(channel, term, cols, rows)
    @ccall libssh.ssh_channel_request_pty_size(channel::ssh_channel, term::Ptr{Cchar}, cols::Cint, rows::Cint)::Cint
end

"""
    ssh_channel_request_pty_size_modes(channel, term, cols, rows, modes, modes_len)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga2ebd34c7f15182e9fc1dde66863cf8d9).
"""
function ssh_channel_request_pty_size_modes(channel, term, cols, rows, modes, modes_len)
    @ccall libssh.ssh_channel_request_pty_size_modes(channel::ssh_channel, term::Ptr{Cchar}, cols::Cint, rows::Cint, modes::Ptr{Cuchar}, modes_len::Csize_t)::Cint
end

"""
    ssh_channel_request_shell(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gaed4c5fb30c9df2b2548421ccf4e81bf1).
"""
function ssh_channel_request_shell(channel)
    @ccall libssh.ssh_channel_request_shell(channel::ssh_channel)::Cint
end

"""
    ssh_channel_request_send_signal(channel, signum)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gaa98315fca818b561970a6950683f4053).
"""
function ssh_channel_request_send_signal(channel, signum)
    @ccall libssh.ssh_channel_request_send_signal(channel::ssh_channel, signum::Ptr{Cchar})::Cint
end

"""
    ssh_channel_request_send_break(channel, length)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gaef198ad0dcf0968aa2a449c8898d985e).
"""
function ssh_channel_request_send_break(channel, length)
    @ccall libssh.ssh_channel_request_send_break(channel::ssh_channel, length::UInt32)::Cint
end

"""
    ssh_channel_request_sftp(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga3d2a402cddd799036006294eb61649fe).
"""
function ssh_channel_request_sftp(channel)
    @ccall libssh.ssh_channel_request_sftp(channel::ssh_channel)::Cint
end

"""
    ssh_channel_request_subsystem(channel, subsystem)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga06024b070f9b2a3d6964b79ae36695b7).
"""
function ssh_channel_request_subsystem(channel, subsystem)
    @ccall libssh.ssh_channel_request_subsystem(channel::ssh_channel, subsystem::Ptr{Cchar})::Cint
end

"""
    ssh_channel_request_x11(channel, single_connection, protocol, cookie, screen_number)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gadfa34624c28164bd73453cd04aa64c1f).
"""
function ssh_channel_request_x11(channel, single_connection, protocol, cookie, screen_number)
    @ccall libssh.ssh_channel_request_x11(channel::ssh_channel, single_connection::Cint, protocol::Ptr{Cchar}, cookie::Ptr{Cchar}, screen_number::Cint)::Cint
end

"""
    ssh_channel_request_auth_agent(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gab2e28b520b8f8fe5ff5626de2a4113d9).
"""
function ssh_channel_request_auth_agent(channel)
    @ccall libssh.ssh_channel_request_auth_agent(channel::ssh_channel)::Cint
end

"""
    ssh_channel_send_eof(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga072f82fdf3e50514f747653af2c99004).
"""
function ssh_channel_send_eof(channel)
    @ccall libssh.ssh_channel_send_eof(channel::ssh_channel)::Cint
end

"""
    ssh_channel_set_blocking(channel, blocking)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga1c00ed18679d9a8c5b971260b5df13a2).
"""
function ssh_channel_set_blocking(channel, blocking)
    @ccall libssh.ssh_channel_set_blocking(channel::ssh_channel, blocking::Cint)::Cvoid
end

"""
    ssh_channel_set_counter(channel, counter)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gab0649fe21b7a900b4a8e10ecb3401395).
"""
function ssh_channel_set_counter(channel, counter)
    @ccall libssh.ssh_channel_set_counter(channel::ssh_channel, counter::ssh_counter)::Cvoid
end

"""
    ssh_channel_write(channel, data, len)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga5d658df773ba854b35ff9f905341e2fb).
"""
function ssh_channel_write(channel, data, len)
    @ccall libssh.ssh_channel_write(channel::ssh_channel, data::Ptr{Cvoid}, len::UInt32)::Cint
end

"""
    ssh_channel_write_stderr(channel, data, len)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga7ebd0ed490ee4485c6d5feb7d22bc162).
"""
function ssh_channel_write_stderr(channel, data, len)
    @ccall libssh.ssh_channel_write_stderr(channel::ssh_channel, data::Ptr{Cvoid}, len::UInt32)::Cint
end

"""
    ssh_channel_window_size(channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gadf53c5a5b501086af26d06cba3f1491f).
"""
function ssh_channel_window_size(channel)
    @ccall libssh.ssh_channel_window_size(channel::ssh_channel)::UInt32
end

"""
    ssh_basename(path)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__misc.html#gaf740c71ef920d28d647c9dfeabcbc07d).
"""
function ssh_basename(path)
    @ccall libssh.ssh_basename(path::Ptr{Cchar})::Ptr{Cchar}
end

"""
    ssh_clean_pubkey_hash(hash)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga07827fd70a51ddc4030364f220eb4c9c).
"""
function ssh_clean_pubkey_hash(hash)
    @ccall libssh.ssh_clean_pubkey_hash(hash::Ptr{Ptr{Cuchar}})::Cvoid
end

"""
    ssh_connect(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga032e07cbd8bc3f14cb2dd375db0b03d7).
"""
function ssh_connect(session)
    @ccall libssh.ssh_connect(session::ssh_session)::Cint
end

function ssh_connector_new(session)
    @ccall libssh.ssh_connector_new(session::ssh_session)::ssh_connector
end

function ssh_connector_free(connector)
    @ccall libssh.ssh_connector_free(connector::ssh_connector)::Cvoid
end

function ssh_connector_set_in_channel(connector, channel, flags)
    @ccall libssh.ssh_connector_set_in_channel(connector::ssh_connector, channel::ssh_channel, flags::ssh_connector_flags_e)::Cint
end

function ssh_connector_set_out_channel(connector, channel, flags)
    @ccall libssh.ssh_connector_set_out_channel(connector::ssh_connector, channel::ssh_channel, flags::ssh_connector_flags_e)::Cint
end

function ssh_connector_set_in_fd(connector, fd)
    @ccall libssh.ssh_connector_set_in_fd(connector::ssh_connector, fd::socket_t)::Cvoid
end

function ssh_connector_set_out_fd(connector, fd)
    @ccall libssh.ssh_connector_set_out_fd(connector::ssh_connector, fd::socket_t)::Cvoid
end

"""
    ssh_copyright()

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga68204f158313194f5691728b70034471).
"""
function ssh_copyright()
    @ccall libssh.ssh_copyright()::Ptr{Cchar}
end

"""
    ssh_disconnect(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga0f048a4c0dbe02cfb7e9c5b6d0db0f27).
"""
function ssh_disconnect(session)
    @ccall libssh.ssh_disconnect(session::ssh_session)::Cvoid
end

"""
    ssh_dirname(path)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__misc.html#ga0f373b623286de58e72a0c939f547539).
"""
function ssh_dirname(path)
    @ccall libssh.ssh_dirname(path::Ptr{Cchar})::Ptr{Cchar}
end

"""
    ssh_finalize()

[Upstream documentation](https://api.libssh.org/stable/group__libssh.html#ga94a851d00248acde9cd7da084b491242).
"""
function ssh_finalize()
    @ccall libssh.ssh_finalize()::Cint
end

"""
    ssh_channel_open_forward_port(session, timeout_ms, destination_port, originator, originator_port)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga4dce3b5fb6755ec0f610846b220f50ff).
"""
function ssh_channel_open_forward_port(session, timeout_ms, destination_port, originator, originator_port)
    @ccall libssh.ssh_channel_open_forward_port(session::ssh_session, timeout_ms::Cint, destination_port::Ptr{Cint}, originator::Ptr{Ptr{Cchar}}, originator_port::Ptr{Cint})::ssh_channel
end

"""
    ssh_channel_accept_forward(session, timeout_ms, destination_port)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga490e4b0a7adc022507b7f165b336afe4).
"""
function ssh_channel_accept_forward(session, timeout_ms, destination_port)
    @ccall libssh.ssh_channel_accept_forward(session::ssh_session, timeout_ms::Cint, destination_port::Ptr{Cint})::ssh_channel
end

"""
    ssh_channel_cancel_forward(session, address, port)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga3bff751afc5ecb5bbf9d6447e4e5370f).
"""
function ssh_channel_cancel_forward(session, address, port)
    @ccall libssh.ssh_channel_cancel_forward(session::ssh_session, address::Ptr{Cchar}, port::Cint)::Cint
end

"""
    ssh_channel_listen_forward(session, address, port, bound_port)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga758cda957227751870c8772df46e5b39).
"""
function ssh_channel_listen_forward(session, address, port, bound_port)
    @ccall libssh.ssh_channel_listen_forward(session::ssh_session, address::Ptr{Cchar}, port::Cint, bound_port::Ptr{Cint})::Cint
end

"""
    ssh_free(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gae5af27a98a7488e9f5ded6b37c274156).
"""
function ssh_free(session)
    @ccall libssh.ssh_free(session::ssh_session)::Cvoid
end

"""
    ssh_get_disconnect_message(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga098a2c56b8b1a965189badeb99f0dda5).
"""
function ssh_get_disconnect_message(session)
    @ccall libssh.ssh_get_disconnect_message(session::ssh_session)::Ptr{Cchar}
end

"""
    ssh_get_error(error)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__error.html#ga38f8c38cecec04257bf81a7f5c4c01d8).
"""
function ssh_get_error(error)
    @ccall libssh.ssh_get_error(error::Ptr{Cvoid})::Ptr{Cchar}
end

"""
    ssh_get_error_code(error)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__error.html#ga036433b7bf3d4ca94206253f58d136f9).
"""
function ssh_get_error_code(error)
    @ccall libssh.ssh_get_error_code(error::Ptr{Cvoid})::Cint
end

"""
    ssh_get_fd(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gafe509fcea47714b5cd277d1e35e83276).
"""
function ssh_get_fd(session)
    @ccall libssh.ssh_get_fd(session::ssh_session)::socket_t
end

"""
    ssh_get_hexa(what, len)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__misc.html#ga93a317d97ed7de30084d784f851acd8b).
"""
function ssh_get_hexa(what, len)
    @ccall libssh.ssh_get_hexa(what::Ptr{Cuchar}, len::Csize_t)::Ptr{Cchar}
end

"""
    ssh_get_issue_banner(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga253b7be75715accea81f48cb2df7446c).
"""
function ssh_get_issue_banner(session)
    @ccall libssh.ssh_get_issue_banner(session::ssh_session)::Ptr{Cchar}
end

"""
    ssh_get_openssh_version(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gac55d2895467a1e898ee75b4710d836a5).
"""
function ssh_get_openssh_version(session)
    @ccall libssh.ssh_get_openssh_version(session::ssh_session)::Cint
end

"""
    ssh_request_no_more_sessions(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gaa1819f532a57fb455704c227341f386b).
"""
function ssh_request_no_more_sessions(session)
    @ccall libssh.ssh_request_no_more_sessions(session::ssh_session)::Cint
end

"""
    ssh_get_server_publickey(session, key)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga5342eefee0497636e9657c968e106782).
"""
function ssh_get_server_publickey(session, key)
    @ccall libssh.ssh_get_server_publickey(session::ssh_session, key::Ptr{ssh_key})::Cint
end

@cenum ssh_publickey_hash_type::UInt32 begin
    SSH_PUBLICKEY_HASH_SHA1 = 0
    SSH_PUBLICKEY_HASH_MD5 = 1
    SSH_PUBLICKEY_HASH_SHA256 = 2
end

"""
    ssh_get_publickey_hash(key, type, hash, hlen)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga7a7b16a4bed6d8d58f10bdb269172ff7).
"""
function ssh_get_publickey_hash(key, type, hash, hlen)
    @ccall libssh.ssh_get_publickey_hash(key::ssh_key, type::ssh_publickey_hash_type, hash::Ptr{Ptr{Cuchar}}, hlen::Ptr{Csize_t})::Cint
end

"""
    ssh_get_pubkey_hash(session, hash)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gaf8ff0e2236d54d964a82f68d7323a741).
"""
function ssh_get_pubkey_hash(session, hash)
    @ccall libssh.ssh_get_pubkey_hash(session::ssh_session, hash::Ptr{Ptr{Cuchar}})::Cint
end

function ssh_forward_accept(session, timeout_ms)
    @ccall libssh.ssh_forward_accept(session::ssh_session, timeout_ms::Cint)::ssh_channel
end

function ssh_forward_cancel(session, address, port)
    @ccall libssh.ssh_forward_cancel(session::ssh_session, address::Ptr{Cchar}, port::Cint)::Cint
end

function ssh_forward_listen(session, address, port, bound_port)
    @ccall libssh.ssh_forward_listen(session::ssh_session, address::Ptr{Cchar}, port::Cint, bound_port::Ptr{Cint})::Cint
end

"""
    ssh_get_publickey(session, key)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga839a93298aeff85adbaf4db815b58730).
"""
function ssh_get_publickey(session, key)
    @ccall libssh.ssh_get_publickey(session::ssh_session, key::Ptr{ssh_key})::Cint
end

"""
    ssh_write_knownhost(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gaf61a9cfdc40c76ffce9f9a8543755d36).
"""
function ssh_write_knownhost(session)
    @ccall libssh.ssh_write_knownhost(session::ssh_session)::Cint
end

"""
    ssh_dump_knownhost(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga5b2e4951daf6da980dbaea3ac8e0dee1).
"""
function ssh_dump_knownhost(session)
    @ccall libssh.ssh_dump_knownhost(session::ssh_session)::Ptr{Cchar}
end

"""
    ssh_is_server_known(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga6f37e3d7bb6b938b44d6a34a76fdfa0b).
"""
function ssh_is_server_known(session)
    @ccall libssh.ssh_is_server_known(session::ssh_session)::Cint
end

"""
    ssh_print_hexa(descr, what, len)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__misc.html#ga39bf7936ed51361fe9cf3c3bbfc25514).
"""
function ssh_print_hexa(descr, what, len)
    @ccall libssh.ssh_print_hexa(descr::Ptr{Cchar}, what::Ptr{Cuchar}, len::Csize_t)::Cvoid
end

"""
    ssh_channel_select(readchans, writechans, exceptchans, timeout)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga1026cfa48ecfc0b4898d4ea443acfc5d).
"""
function ssh_channel_select(readchans, writechans, exceptchans, timeout)
    @ccall libssh.ssh_channel_select(readchans::Ptr{ssh_channel}, writechans::Ptr{ssh_channel}, exceptchans::Ptr{ssh_channel}, timeout::Ptr{Cvoid})::Cint
end

"""
    ssh_scp_accept_request(scp)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#gad3bb38b15f02597cc1e155c526a51e51).
"""
function ssh_scp_accept_request(scp)
    @ccall libssh.ssh_scp_accept_request(scp::ssh_scp)::Cint
end

"""
    ssh_scp_close(scp)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#ga14d31059dcf6fb2325fb960da8e4474e).
"""
function ssh_scp_close(scp)
    @ccall libssh.ssh_scp_close(scp::ssh_scp)::Cint
end

"""
    ssh_scp_deny_request(scp, reason)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#gad36438c6b1e235d96cec43ca350e9b4f).
"""
function ssh_scp_deny_request(scp, reason)
    @ccall libssh.ssh_scp_deny_request(scp::ssh_scp, reason::Ptr{Cchar})::Cint
end

"""
    ssh_scp_free(scp)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#gac29000cdb07c74d54251fbd838c0c661).
"""
function ssh_scp_free(scp)
    @ccall libssh.ssh_scp_free(scp::ssh_scp)::Cvoid
end

"""
    ssh_scp_init(scp)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#ga1db56dcb9dee01dd0b679b3b11151110).
"""
function ssh_scp_init(scp)
    @ccall libssh.ssh_scp_init(scp::ssh_scp)::Cint
end

"""
    ssh_scp_leave_directory(scp)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#ga2ca698c1e49612c083d9f8a72df52188).
"""
function ssh_scp_leave_directory(scp)
    @ccall libssh.ssh_scp_leave_directory(scp::ssh_scp)::Cint
end

"""
    ssh_scp_new(session, mode, location)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#ga9fcd39a2bb6438e39cf19ff859dc2f2e).
"""
function ssh_scp_new(session, mode, location)
    @ccall libssh.ssh_scp_new(session::ssh_session, mode::Cint, location::Ptr{Cchar})::ssh_scp
end

"""
    ssh_scp_pull_request(scp)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#gaba59cd8cc77d219cac93f865445c6e47).
"""
function ssh_scp_pull_request(scp)
    @ccall libssh.ssh_scp_pull_request(scp::ssh_scp)::Cint
end

"""
    ssh_scp_push_directory(scp, dirname, mode)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#gaa584f03d4e3d582ac10a3a19818ec56d).
"""
function ssh_scp_push_directory(scp, dirname, mode)
    @ccall libssh.ssh_scp_push_directory(scp::ssh_scp, dirname::Ptr{Cchar}, mode::Cint)::Cint
end

"""
    ssh_scp_push_file(scp, filename, size, perms)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#ga544f4b9c525071910110ada94148adc6).
"""
function ssh_scp_push_file(scp, filename, size, perms)
    @ccall libssh.ssh_scp_push_file(scp::ssh_scp, filename::Ptr{Cchar}, size::Csize_t, perms::Cint)::Cint
end

"""
    ssh_scp_push_file64(scp, filename, size, perms)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#ga50b701b9c8923011d4fc6489c9c7eaae).
"""
function ssh_scp_push_file64(scp, filename, size, perms)
    @ccall libssh.ssh_scp_push_file64(scp::ssh_scp, filename::Ptr{Cchar}, size::UInt64, perms::Cint)::Cint
end

"""
    ssh_scp_read(scp, buffer, size)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#ga10bf627407959b51a7c39b37e8d46460).
"""
function ssh_scp_read(scp, buffer, size)
    @ccall libssh.ssh_scp_read(scp::ssh_scp, buffer::Ptr{Cvoid}, size::Csize_t)::Cint
end

"""
    ssh_scp_request_get_filename(scp)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#ga675bc6f99a250ac2614d9cfc8776247f).
"""
function ssh_scp_request_get_filename(scp)
    @ccall libssh.ssh_scp_request_get_filename(scp::ssh_scp)::Ptr{Cchar}
end

"""
    ssh_scp_request_get_permissions(scp)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#ga3386eb6df0cc620e74a039974c6280d4).
"""
function ssh_scp_request_get_permissions(scp)
    @ccall libssh.ssh_scp_request_get_permissions(scp::ssh_scp)::Cint
end

"""
    ssh_scp_request_get_size(scp)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#ga8b6f736a5b5af73cf59c7825d7e61966).
"""
function ssh_scp_request_get_size(scp)
    @ccall libssh.ssh_scp_request_get_size(scp::ssh_scp)::Csize_t
end

"""
    ssh_scp_request_get_size64(scp)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#gaefe7f44417e1dc0d857d634fe1117d6d).
"""
function ssh_scp_request_get_size64(scp)
    @ccall libssh.ssh_scp_request_get_size64(scp::ssh_scp)::UInt64
end

"""
    ssh_scp_request_get_warning(scp)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#ga495c037d443a5f0d0d9b61ef79ecc0a8).
"""
function ssh_scp_request_get_warning(scp)
    @ccall libssh.ssh_scp_request_get_warning(scp::ssh_scp)::Ptr{Cchar}
end

"""
    ssh_scp_write(scp, buffer, len)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__scp.html#ga11f48e2cf62bcec20d9232ed3ca41752).
"""
function ssh_scp_write(scp, buffer, len)
    @ccall libssh.ssh_scp_write(scp::ssh_scp, buffer::Ptr{Cvoid}, len::Csize_t)::Cint
end

"""
    ssh_get_random(where, len, strong)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__misc.html#ga64b50434e422c962d21dfc2308eb0f2b).
"""
function ssh_get_random(where, len, strong)
    @ccall libssh.ssh_get_random(where::Ptr{Cvoid}, len::Cint, strong::Cint)::Cint
end

"""
    ssh_get_version(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga8467735e4735165336f68ee82e24de0e).
"""
function ssh_get_version(session)
    @ccall libssh.ssh_get_version(session::ssh_session)::Cint
end

"""
    ssh_get_status(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gac199314d1646372c566ef14b9b6dca53).
"""
function ssh_get_status(session)
    @ccall libssh.ssh_get_status(session::ssh_session)::Cint
end

"""
    ssh_get_poll_flags(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gae9d0104fbeca17bcfb0659ad718c4606).
"""
function ssh_get_poll_flags(session)
    @ccall libssh.ssh_get_poll_flags(session::ssh_session)::Cint
end

"""
    ssh_init()

[Upstream documentation](https://api.libssh.org/stable/group__libssh.html#ga3ebf8d6920e563f3b032e3cd5277598e).
"""
function ssh_init()
    @ccall libssh.ssh_init()::Cint
end

"""
    ssh_is_blocking(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga0c959bde817801ac5de2db1e64b52f26).
"""
function ssh_is_blocking(session)
    @ccall libssh.ssh_is_blocking(session::ssh_session)::Cint
end

"""
    ssh_is_connected(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga49d8f413a3c7879070a112703de1d6e2).
"""
function ssh_is_connected(session)
    @ccall libssh.ssh_is_connected(session::ssh_session)::Cint
end

"""
    ssh_known_hosts_parse_line(host, line, entry)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gaa3a37302850d0467f19db4eba5257d3d).
"""
function ssh_known_hosts_parse_line(host, line, entry)
    @ccall libssh.ssh_known_hosts_parse_line(host::Ptr{Cchar}, line::Ptr{Cchar}, entry::Ptr{Ptr{ssh_knownhosts_entry}})::Cint
end

"""
    ssh_session_has_known_hosts_entry(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gaffea2fa1210919f833a081739734476d).
"""
function ssh_session_has_known_hosts_entry(session)
    @ccall libssh.ssh_session_has_known_hosts_entry(session::ssh_session)::ssh_known_hosts_e
end

"""
    ssh_session_export_known_hosts_entry(session, pentry_string)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga519c3985c8803c67d24ce9f937e3da9a).
"""
function ssh_session_export_known_hosts_entry(session, pentry_string)
    @ccall libssh.ssh_session_export_known_hosts_entry(session::ssh_session, pentry_string::Ptr{Ptr{Cchar}})::Cint
end

"""
    ssh_session_update_known_hosts(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga958fdd1aedcd85a5c496c0aa22362d34).
"""
function ssh_session_update_known_hosts(session)
    @ccall libssh.ssh_session_update_known_hosts(session::ssh_session)::Cint
end

"""
    ssh_session_get_known_hosts_entry(session, pentry)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga874d3246c9c9bfc7040302e10650bce8).
"""
function ssh_session_get_known_hosts_entry(session, pentry)
    @ccall libssh.ssh_session_get_known_hosts_entry(session::ssh_session, pentry::Ptr{Ptr{ssh_knownhosts_entry}})::ssh_known_hosts_e
end

"""
    ssh_session_is_known_server(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gacbc5d04fe66beee863a0c61a93fdf765).
"""
function ssh_session_is_known_server(session)
    @ccall libssh.ssh_session_is_known_server(session::ssh_session)::ssh_known_hosts_e
end

"""
    ssh_set_log_level(level)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__log.html#ga9719dabb8fab8a3ebeb4dc2ebcd2dd45).
"""
function ssh_set_log_level(level)
    @ccall libssh.ssh_set_log_level(level::Cint)::Cint
end

"""
    ssh_get_log_level()

[Upstream documentation](https://api.libssh.org/stable/group__libssh__log.html#gad6a0b7b581b12be4e34a110b7312614b).
"""
function ssh_get_log_level()
    @ccall libssh.ssh_get_log_level()::Cint
end

"""
    ssh_get_log_userdata()

[Upstream documentation](https://api.libssh.org/stable/group__libssh__log.html#ga4e556bbd212f63ddb88b0640473c532b).
"""
function ssh_get_log_userdata()
    @ccall libssh.ssh_get_log_userdata()::Ptr{Cvoid}
end

"""
    ssh_set_log_userdata(data)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__log.html#ga0addd5c29922f40e9f842a43e0cb0b27).
"""
function ssh_set_log_userdata(data)
    @ccall libssh.ssh_set_log_userdata(data::Ptr{Cvoid})::Cint
end

function ssh_message_channel_request_open_reply_accept(msg)
    @ccall libssh.ssh_message_channel_request_open_reply_accept(msg::ssh_message)::ssh_channel
end

function ssh_message_channel_request_open_reply_accept_channel(msg, chan)
    @ccall libssh.ssh_message_channel_request_open_reply_accept_channel(msg::ssh_message, chan::ssh_channel)::Cint
end

function ssh_message_channel_request_reply_success(msg)
    @ccall libssh.ssh_message_channel_request_reply_success(msg::ssh_message)::Cint
end

"""
    ssh_message_get(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__messages.html#ga8e536b6f1c824b7ca43d0e8f954b3bd4).
"""
function ssh_message_get(session)
    @ccall libssh.ssh_message_get(session::ssh_session)::ssh_message
end

"""
    ssh_message_subtype(msg)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__messages.html#ga7aa19d51c443b779fe454f0be3c666d4).
"""
function ssh_message_subtype(msg)
    @ccall libssh.ssh_message_subtype(msg::ssh_message)::Cint
end

"""
    ssh_message_type(msg)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__messages.html#ga20fc6e536f170b98c7d62ce3675d8cdb).
"""
function ssh_message_type(msg)
    @ccall libssh.ssh_message_type(msg::ssh_message)::Cint
end

"""
    ssh_mkdir(pathname, mode)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__misc.html#ga5e15e93beecaef3af67d02b7ba55309f).
"""
function ssh_mkdir(pathname, mode)
    @ccall libssh.ssh_mkdir(pathname::Ptr{Cchar}, mode::mode_t)::Cint
end

"""
    ssh_new()

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gaadadc0f9601547c30db7c4d62017d32c).
"""
function ssh_new()
    @ccall libssh.ssh_new()::ssh_session
end

"""
    ssh_options_copy(src, dest)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gaead8cef1f39e785139bc510852ce1dff).
"""
function ssh_options_copy(src, dest)
    @ccall libssh.ssh_options_copy(src::ssh_session, dest::Ptr{ssh_session})::Cint
end

"""
    ssh_options_getopt(session, argcptr, argv)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga93f7f7159893f3ce62c9b178724eff75).
"""
function ssh_options_getopt(session, argcptr, argv)
    @ccall libssh.ssh_options_getopt(session::ssh_session, argcptr::Ptr{Cint}, argv::Ptr{Ptr{Cchar}})::Cint
end

"""
    ssh_options_parse_config(session, filename)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga82371e723260c7572ea061edecc2e9f1).
"""
function ssh_options_parse_config(session, filename)
    @ccall libssh.ssh_options_parse_config(session::ssh_session, filename::Ptr{Cchar})::Cint
end

"""
    ssh_options_set(session, type, value; throw = true)

Auto-generated wrapper around [`ssh_options_set()`](https://api.libssh.org/stable/group__libssh__session.html#ga7a801b85800baa3f4e16f5b47db0a73d).
"""
function ssh_options_set(session, type, value; throw = true)
    ret = @ccall(libssh.ssh_options_set(session::ssh_session, type::ssh_options_e, value::Ptr{Cvoid})::Cint)
    if ret != SSH_OK && throw
        Base.throw(LibSSHException("Error from ssh_options_set, did not return SSH_OK: " * "$(ret)"))
    end
    return ret
end

"""
    ssh_options_get(session, type, value; throw = true)

Auto-generated wrapper around [`ssh_options_get()`](https://api.libssh.org/stable/group__libssh__session.html#gaaa9d400920cad4d6e4a0fb09ff8c7b01).
"""
function ssh_options_get(session, type, value; throw = true)
    ret = @ccall(libssh.ssh_options_get(session::ssh_session, type::ssh_options_e, value::Ptr{Ptr{Cchar}})::Cint)
    if ret != SSH_OK && throw
        Base.throw(LibSSHException("Error from ssh_options_get, did not return SSH_OK: " * "$(ret)"))
    end
    return ret
end

"""
    ssh_options_get_port(session, port_target; throw = true)

Auto-generated wrapper around [`ssh_options_get_port()`](https://api.libssh.org/stable/group__libssh__session.html#gaa298d8445355420d80f2d968477ba86f).
"""
function ssh_options_get_port(session, port_target; throw = true)
    ret = @ccall(libssh.ssh_options_get_port(session::ssh_session, port_target::Ptr{Cuint})::Cint)
    if ret != SSH_OK && throw
        Base.throw(LibSSHException("Error from ssh_options_get_port, did not return SSH_OK: " * "$(ret)"))
    end
    return ret
end

function ssh_pcap_file_close(pcap)
    @ccall libssh.ssh_pcap_file_close(pcap::ssh_pcap_file)::Cint
end

function ssh_pcap_file_free(pcap)
    @ccall libssh.ssh_pcap_file_free(pcap::ssh_pcap_file)::Cvoid
end

function ssh_pcap_file_new()
    @ccall libssh.ssh_pcap_file_new()::ssh_pcap_file
end

function ssh_pcap_file_open(pcap, filename)
    @ccall libssh.ssh_pcap_file_open(pcap::ssh_pcap_file, filename::Ptr{Cchar})::Cint
end

# typedef int ( * ssh_auth_callback ) ( const char * prompt , char * buf , size_t len , int echo , int verify , void * userdata )
"""
SSH authentication callback for password and publickey auth.

# Arguments
* `prompt`: Prompt to be displayed.
* `buf`: Buffer to save the password. You should null-terminate it.
* `len`: Length of the buffer.
* `echo`: Enable or disable the echo of what you type.
* `verify`: Should the password be verified?
* `userdata`: Userdata to be passed to the callback function. Useful for GUI applications.
# Returns
0 on success, < 0 on error.
"""
const ssh_auth_callback = Ptr{Cvoid}

"""
    ssh_file_format_e

@}
"""
@cenum ssh_file_format_e::UInt32 begin
    SSH_FILE_FORMAT_DEFAULT = 0
    SSH_FILE_FORMAT_OPENSSH = 1
    SSH_FILE_FORMAT_PEM = 2
end

"""
    ssh_key_new()

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#gabfebce03474a4d014aa779d5dbf057b0).
"""
function ssh_key_new()
    @ccall libssh.ssh_key_new()::ssh_key
end

"""
    ssh_key_type(key)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga9cb4a857f8e510f80cfc38e46c476490).
"""
function ssh_key_type(key)
    @ccall libssh.ssh_key_type(key::ssh_key)::ssh_keytypes_e
end

"""
    ssh_key_type_to_char(type)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga5fe1b765026d6911e12f764d1ad37bf0).
"""
function ssh_key_type_to_char(type)
    @ccall libssh.ssh_key_type_to_char(type::ssh_keytypes_e)::Ptr{Cchar}
end

"""
    ssh_key_type_from_name(name)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga44584f2316c6ccd40e9939454335d8bc).
"""
function ssh_key_type_from_name(name)
    @ccall libssh.ssh_key_type_from_name(name::Ptr{Cchar})::ssh_keytypes_e
end

"""
    ssh_key_is_public(k)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga9bc688b5cbc400320ac44896eba21924).
"""
function ssh_key_is_public(k)
    @ccall libssh.ssh_key_is_public(k::ssh_key)::Cint
end

"""
    ssh_key_is_private(k)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga09de68aba0a7c4e31d8ba7df43b637c5).
"""
function ssh_key_is_private(k)
    @ccall libssh.ssh_key_is_private(k::ssh_key)::Cint
end

"""
    ssh_key_cmp(k1, k2, what)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga4dc33945294c2bbd671365a9d3db8e2f).
"""
function ssh_key_cmp(k1, k2, what)
    @ccall libssh.ssh_key_cmp(k1::ssh_key, k2::ssh_key, what::ssh_keycmp_e)::Cint
end

"""
    ssh_key_dup(key)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#gae0944d085d1a63c73b7eaf78924ddca8).
"""
function ssh_key_dup(key)
    @ccall libssh.ssh_key_dup(key::ssh_key)::ssh_key
end

"""
    ssh_pki_generate(type, parameter, pkey)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#gae038fa1b34f9427c7ba84082a1a20bad).
"""
function ssh_pki_generate(type, parameter, pkey)
    @ccall libssh.ssh_pki_generate(type::ssh_keytypes_e, parameter::Cint, pkey::Ptr{ssh_key})::Cint
end

"""
    ssh_pki_import_privkey_base64(b64_key, passphrase, auth_fn, auth_data, pkey)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga5f2a2ca4b9b711d1c1af8020dfbd4a53).
"""
function ssh_pki_import_privkey_base64(b64_key, passphrase, auth_fn, auth_data, pkey)
    @ccall libssh.ssh_pki_import_privkey_base64(b64_key::Ptr{Cchar}, passphrase::Ptr{Cchar}, auth_fn::ssh_auth_callback, auth_data::Ptr{Cvoid}, pkey::Ptr{ssh_key})::Cint
end

"""
    ssh_pki_export_privkey_base64(privkey, passphrase, auth_fn, auth_data, b64_key)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga320970245fa4e3ab873888b581e13378).
"""
function ssh_pki_export_privkey_base64(privkey, passphrase, auth_fn, auth_data, b64_key)
    @ccall libssh.ssh_pki_export_privkey_base64(privkey::ssh_key, passphrase::Ptr{Cchar}, auth_fn::ssh_auth_callback, auth_data::Ptr{Cvoid}, b64_key::Ptr{Ptr{Cchar}})::Cint
end

"""
    ssh_pki_export_privkey_base64_format(privkey, passphrase, auth_fn, auth_data, b64_key, format)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga116c23be7ef4c9482a147ff1316a98d7).
"""
function ssh_pki_export_privkey_base64_format(privkey, passphrase, auth_fn, auth_data, b64_key, format)
    @ccall libssh.ssh_pki_export_privkey_base64_format(privkey::ssh_key, passphrase::Ptr{Cchar}, auth_fn::ssh_auth_callback, auth_data::Ptr{Cvoid}, b64_key::Ptr{Ptr{Cchar}}, format::ssh_file_format_e)::Cint
end

"""
    ssh_pki_import_privkey_file(filename, passphrase, auth_fn, auth_data, pkey)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga1c8f84137606b1585006302499100ee0).
"""
function ssh_pki_import_privkey_file(filename, passphrase, auth_fn, auth_data, pkey)
    @ccall libssh.ssh_pki_import_privkey_file(filename::Ptr{Cchar}, passphrase::Ptr{Cchar}, auth_fn::ssh_auth_callback, auth_data::Ptr{Cvoid}, pkey::Ptr{ssh_key})::Cint
end

"""
    ssh_pki_export_privkey_file(privkey, passphrase, auth_fn, auth_data, filename)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga3b294c44e2280c935cb0b82ede5c42ee).
"""
function ssh_pki_export_privkey_file(privkey, passphrase, auth_fn, auth_data, filename)
    @ccall libssh.ssh_pki_export_privkey_file(privkey::ssh_key, passphrase::Ptr{Cchar}, auth_fn::ssh_auth_callback, auth_data::Ptr{Cvoid}, filename::Ptr{Cchar})::Cint
end

"""
    ssh_pki_export_privkey_file_format(privkey, passphrase, auth_fn, auth_data, filename, format)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#gadfe9d252a36bc0693b4b7fd3c840cded).
"""
function ssh_pki_export_privkey_file_format(privkey, passphrase, auth_fn, auth_data, filename, format)
    @ccall libssh.ssh_pki_export_privkey_file_format(privkey::ssh_key, passphrase::Ptr{Cchar}, auth_fn::ssh_auth_callback, auth_data::Ptr{Cvoid}, filename::Ptr{Cchar}, format::ssh_file_format_e)::Cint
end

"""
    ssh_pki_copy_cert_to_privkey(cert_key, privkey)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga71432844d5d210d63a92acff86f91e90).
"""
function ssh_pki_copy_cert_to_privkey(cert_key, privkey)
    @ccall libssh.ssh_pki_copy_cert_to_privkey(cert_key::ssh_key, privkey::ssh_key)::Cint
end

"""
    ssh_pki_import_pubkey_base64(b64_key, type, pkey)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#gac8d7d3fa88b93d8b059b6b5b2f457913).
"""
function ssh_pki_import_pubkey_base64(b64_key, type, pkey)
    @ccall libssh.ssh_pki_import_pubkey_base64(b64_key::Ptr{Cchar}, type::ssh_keytypes_e, pkey::Ptr{ssh_key})::Cint
end

"""
    ssh_pki_import_pubkey_file(filename, pkey)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#gaffb08168b870fb9e86cc7649c8987eb0).
"""
function ssh_pki_import_pubkey_file(filename, pkey)
    @ccall libssh.ssh_pki_import_pubkey_file(filename::Ptr{Cchar}, pkey::Ptr{ssh_key})::Cint
end

"""
    ssh_pki_import_cert_base64(b64_cert, type, pkey)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga78c1f26eac4345a56749b4e086d9fa28).
"""
function ssh_pki_import_cert_base64(b64_cert, type, pkey)
    @ccall libssh.ssh_pki_import_cert_base64(b64_cert::Ptr{Cchar}, type::ssh_keytypes_e, pkey::Ptr{ssh_key})::Cint
end

"""
    ssh_pki_import_cert_file(filename, pkey)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga95cb20de349b935e9d997327674d7065).
"""
function ssh_pki_import_cert_file(filename, pkey)
    @ccall libssh.ssh_pki_import_cert_file(filename::Ptr{Cchar}, pkey::Ptr{ssh_key})::Cint
end

"""
    ssh_pki_export_privkey_to_pubkey(privkey, pkey)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga5777bc537da6a447b2a9aa9eceff9877).
"""
function ssh_pki_export_privkey_to_pubkey(privkey, pkey)
    @ccall libssh.ssh_pki_export_privkey_to_pubkey(privkey::ssh_key, pkey::Ptr{ssh_key})::Cint
end

"""
    ssh_pki_export_pubkey_base64(key, b64_key)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga2caa40cbd9620e9f7e3e7ab654b256c5).
"""
function ssh_pki_export_pubkey_base64(key, b64_key)
    @ccall libssh.ssh_pki_export_pubkey_base64(key::ssh_key, b64_key::Ptr{Ptr{Cchar}})::Cint
end

"""
    ssh_pki_export_pubkey_file(key, filename)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga576cb3a5c7f40a0e20a88b14a023613d).
"""
function ssh_pki_export_pubkey_file(key, filename)
    @ccall libssh.ssh_pki_export_pubkey_file(key::ssh_key, filename::Ptr{Cchar})::Cint
end

"""
    ssh_pki_key_ecdsa_name(key)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__pki.html#ga186432b29dc912c0857182943e524dea).
"""
function ssh_pki_key_ecdsa_name(key)
    @ccall libssh.ssh_pki_key_ecdsa_name(key::ssh_key)::Ptr{Cchar}
end

"""
    ssh_get_fingerprint_hash(type, hash, len)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga347dcf84a03ca296c653ceb583108bd1).
"""
function ssh_get_fingerprint_hash(type, hash, len)
    @ccall libssh.ssh_get_fingerprint_hash(type::ssh_publickey_hash_type, hash::Ptr{Cuchar}, len::Csize_t)::Ptr{Cchar}
end

"""
    ssh_print_hash(type, hash, len)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga93e85883ddac5198ed590e36eef4dc3b).
"""
function ssh_print_hash(type, hash, len)
    @ccall libssh.ssh_print_hash(type::ssh_publickey_hash_type, hash::Ptr{Cuchar}, len::Csize_t)::Cvoid
end

"""
    ssh_send_ignore(session, data)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gab8827415fd19cf6cb64e7fc83c09e423).
"""
function ssh_send_ignore(session, data)
    @ccall libssh.ssh_send_ignore(session::ssh_session, data::Ptr{Cchar})::Cint
end

"""
    ssh_send_debug(session, message, always_display)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga5ffa2201152e29cc680c4b8e4a3f4fdf).
"""
function ssh_send_debug(session, message, always_display)
    @ccall libssh.ssh_send_debug(session::ssh_session, message::Ptr{Cchar}, always_display::Cint)::Cint
end

function ssh_gssapi_set_creds(session, creds)
    @ccall libssh.ssh_gssapi_set_creds(session::ssh_session, creds::ssh_gssapi_creds)::Cvoid
end

"""
    ssh_select(channels, outchannels, maxfd, readfds, timeout)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga86cbf041bced56d18a2a5248c46cecb4).
"""
function ssh_select(channels, outchannels, maxfd, readfds, timeout)
    @ccall libssh.ssh_select(channels::Ptr{ssh_channel}, outchannels::Ptr{ssh_channel}, maxfd::socket_t, readfds::Ptr{fd_set}, timeout::Ptr{Cvoid})::Cint
end

function ssh_service_request(session, service)
    @ccall libssh.ssh_service_request(session::ssh_session, service::Ptr{Cchar})::Cint
end

"""
    ssh_set_agent_channel(session, channel)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#ga5cfc7675941d8f82f6c9d08fb020f40e).
"""
function ssh_set_agent_channel(session, channel)
    @ccall libssh.ssh_set_agent_channel(session::ssh_session, channel::ssh_channel)::Cint
end

"""
    ssh_set_agent_socket(session, fd)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#ga925a9b6033c304eb6dfb426541f84184).
"""
function ssh_set_agent_socket(session, fd)
    @ccall libssh.ssh_set_agent_socket(session::ssh_session, fd::socket_t)::Cint
end

"""
    ssh_set_blocking(session, blocking)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga2a29cff08855611be84d050e5bec73bc).
"""
function ssh_set_blocking(session, blocking)
    @ccall libssh.ssh_set_blocking(session::ssh_session, blocking::Cint)::Cvoid
end

"""
    ssh_set_counters(session, scounter, rcounter)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga84d4ac53ac8582b70da9b63739df61ad).
"""
function ssh_set_counters(session, scounter, rcounter)
    @ccall libssh.ssh_set_counters(session::ssh_session, scounter::ssh_counter, rcounter::ssh_counter)::Cvoid
end

"""
    ssh_set_fd_except(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga06453278350fd9e940c5c1b0d5225f19).
"""
function ssh_set_fd_except(session)
    @ccall libssh.ssh_set_fd_except(session::ssh_session)::Cvoid
end

"""
    ssh_set_fd_toread(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga0e05c91c6f475eabc8d221914d25a425).
"""
function ssh_set_fd_toread(session)
    @ccall libssh.ssh_set_fd_toread(session::ssh_session)::Cvoid
end

"""
    ssh_set_fd_towrite(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga3f1b3c59662464eec3649d3d72a40543).
"""
function ssh_set_fd_towrite(session)
    @ccall libssh.ssh_set_fd_towrite(session::ssh_session)::Cvoid
end

"""
    ssh_silent_disconnect(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gae1bd16255ba373325adf76307d0c8c42).
"""
function ssh_silent_disconnect(session)
    @ccall libssh.ssh_silent_disconnect(session::ssh_session)::Cvoid
end

function ssh_set_pcap_file(session, pcapfile)
    @ccall libssh.ssh_set_pcap_file(session::ssh_session, pcapfile::ssh_pcap_file)::Cint
end

"""
    ssh_userauth_none(session, username)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#ga58e7c265236edbc97a2f117d3f23b4dd).
"""
function ssh_userauth_none(session, username)
    @ccall libssh.ssh_userauth_none(session::ssh_session, username::Ptr{Cchar})::Cint
end

"""
    ssh_userauth_list(session, username)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#ga35d44897a44b4bb3b7c01108c1812a37).
"""
function ssh_userauth_list(session, username)
    @ccall libssh.ssh_userauth_list(session::ssh_session, username::Ptr{Cchar})::Cint
end

"""
    ssh_userauth_try_publickey(session, username, pubkey)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#ga592f673c4d417a6a46cd4876ac8287aa).
"""
function ssh_userauth_try_publickey(session, username, pubkey)
    @ccall libssh.ssh_userauth_try_publickey(session::ssh_session, username::Ptr{Cchar}, pubkey::ssh_key)::Cint
end

"""
    ssh_userauth_publickey(session, username, privkey)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#gaa38c4f3194ef36720da7eddb0aa99e23).
"""
function ssh_userauth_publickey(session, username, privkey)
    @ccall libssh.ssh_userauth_publickey(session::ssh_session, username::Ptr{Cchar}, privkey::ssh_key)::Cint
end

"""
    ssh_userauth_agent(session, username)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#ga7d84f3f89f65455b80b10e2643d80719).
"""
function ssh_userauth_agent(session, username)
    @ccall libssh.ssh_userauth_agent(session::ssh_session, username::Ptr{Cchar})::Cint
end

"""
    ssh_userauth_publickey_auto_get_current_identity(session, value)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#ga85d2105714189775966d3a1cd2903abf).
"""
function ssh_userauth_publickey_auto_get_current_identity(session, value)
    @ccall libssh.ssh_userauth_publickey_auto_get_current_identity(session::ssh_session, value::Ptr{Ptr{Cchar}})::Cint
end

"""
    ssh_userauth_publickey_auto(session, username, passphrase)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#ga53e6771b250c061463ed98b6e5b6e0af).
"""
function ssh_userauth_publickey_auto(session, username, passphrase)
    @ccall libssh.ssh_userauth_publickey_auto(session::ssh_session, username::Ptr{Cchar}, passphrase::Ptr{Cchar})::Cint
end

"""
    ssh_userauth_password(session, username, password)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#ga50c0c150f8c4703e7ee49b3e3e3ca215).
"""
function ssh_userauth_password(session, username, password)
    @ccall libssh.ssh_userauth_password(session::ssh_session, username::Ptr{Cchar}, password::Ptr{Cchar})::Cint
end

"""
    ssh_userauth_kbdint(session, user, submethods)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#ga6b3b1c2a045286d9476b0252791a07d2).
"""
function ssh_userauth_kbdint(session, user, submethods)
    @ccall libssh.ssh_userauth_kbdint(session::ssh_session, user::Ptr{Cchar}, submethods::Ptr{Cchar})::Cint
end

"""
    ssh_userauth_kbdint_getinstruction(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#gae84514d3836cc976535d032edf3becf3).
"""
function ssh_userauth_kbdint_getinstruction(session)
    @ccall libssh.ssh_userauth_kbdint_getinstruction(session::ssh_session)::Ptr{Cchar}
end

"""
    ssh_userauth_kbdint_getname(session; throw = true)

Auto-generated wrapper around [`ssh_userauth_kbdint_getname()`](https://api.libssh.org/stable/group__libssh__auth.html#ga5d6f5eb0ed09fe2c7a2ac69b972e130e).
"""
function ssh_userauth_kbdint_getname(session; throw = true)
    ret = @ccall(libssh.ssh_userauth_kbdint_getname(session::ssh_session)::Ptr{Cchar})
    if ret == C_NULL
        if throw
            Base.throw(LibSSHException("Error from ssh_userauth_kbdint_getname, no string found (returned C_NULL)"))
        else
            return ret
        end
    end
    return unsafe_string(Ptr{UInt8}(ret))
end

"""
    ssh_userauth_kbdint_getnprompts(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#gacb996ff4979670db009a71a90172ece9).
"""
function ssh_userauth_kbdint_getnprompts(session)
    @ccall libssh.ssh_userauth_kbdint_getnprompts(session::ssh_session)::Cint
end

"""
    ssh_userauth_kbdint_getprompt(session, i, echo; throw = true)

Auto-generated wrapper around [`ssh_userauth_kbdint_getprompt()`](https://api.libssh.org/stable/group__libssh__auth.html#ga15c0f954f79d73e1ac5981ac483efb75).
"""
function ssh_userauth_kbdint_getprompt(session, i, echo; throw = true)
    ret = @ccall(libssh.ssh_userauth_kbdint_getprompt(session::ssh_session, i::Cuint, echo::Ptr{Cchar})::Ptr{Cchar})
    if ret == C_NULL
        if throw
            Base.throw(LibSSHException("Error from ssh_userauth_kbdint_getprompt, no string found (returned C_NULL)"))
        else
            return ret
        end
    end
    return unsafe_string(Ptr{UInt8}(ret))
end

"""
    ssh_userauth_kbdint_getnanswers(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#ga3a98024f73a8bba6afed0b21de513bcd).
"""
function ssh_userauth_kbdint_getnanswers(session)
    @ccall libssh.ssh_userauth_kbdint_getnanswers(session::ssh_session)::Cint
end

"""
    ssh_userauth_kbdint_getanswer(session, i; throw = true)

Auto-generated wrapper around [`ssh_userauth_kbdint_getanswer()`](https://api.libssh.org/stable/group__libssh__auth.html#ga4f55ed8bc6f553423ab1c92598d0194b).
"""
function ssh_userauth_kbdint_getanswer(session, i; throw = true)
    ret = @ccall(libssh.ssh_userauth_kbdint_getanswer(session::ssh_session, i::Cuint)::Ptr{Cchar})
    if ret == C_NULL
        if throw
            Base.throw(LibSSHException("Error from ssh_userauth_kbdint_getanswer, no string found (returned C_NULL)"))
        else
            return ret
        end
    end
    return unsafe_string(Ptr{UInt8}(ret))
end

"""
    ssh_userauth_kbdint_setanswer(session, i, answer)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#ga75e44b1f27059a00080f80fac0107a20).
"""
function ssh_userauth_kbdint_setanswer(session, i, answer)
    @ccall libssh.ssh_userauth_kbdint_setanswer(session::ssh_session, i::Cuint, answer::Ptr{Cchar})::Cint
end

"""
    ssh_userauth_gssapi(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__auth.html#ga2758b0e86a848fe0d1d3d263d2a34d28).
"""
function ssh_userauth_gssapi(session)
    @ccall libssh.ssh_userauth_gssapi(session::ssh_session)::Cint
end

"""
    ssh_version(req_version)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__misc.html#gaf6fc133fcb6792f93b1197b15acf66b0).
"""
function ssh_version(req_version)
    @ccall libssh.ssh_version(req_version::Cint)::Ptr{Cchar}
end

"""
    ssh_string_burn(str)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__string.html#gaca1c58e13e7bdb72ea8410592fa0cbf6).
"""
function ssh_string_burn(str)
    @ccall libssh.ssh_string_burn(str::ssh_string)::Cvoid
end

"""
    ssh_string_copy(str)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__string.html#ga566a98997af205210ed6c24fc5a5cb21).
"""
function ssh_string_copy(str)
    @ccall libssh.ssh_string_copy(str::ssh_string)::ssh_string
end

"""
    ssh_string_data(str)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__string.html#ga977147eebd08ad0619aa6de6218927e7).
"""
function ssh_string_data(str)
    @ccall libssh.ssh_string_data(str::ssh_string)::Ptr{Cvoid}
end

"""
    ssh_string_fill(str, data, len)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__string.html#gad5626768334f4837c4a31e5b4a68d130).
"""
function ssh_string_fill(str, data, len)
    @ccall libssh.ssh_string_fill(str::ssh_string, data::Ptr{Cvoid}, len::Csize_t)::Cint
end

"""
    ssh_string_from_char(what)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__string.html#ga3f4e397885369927a66840626e217137).
"""
function ssh_string_from_char(what)
    @ccall libssh.ssh_string_from_char(what::Ptr{Cchar})::ssh_string
end

"""
    ssh_string_len(str)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__string.html#ga331553369afbfcb4f5300729ed65d0fe).
"""
function ssh_string_len(str)
    @ccall libssh.ssh_string_len(str::ssh_string)::Csize_t
end

"""
    ssh_string_new(size)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__string.html#ga47182accf343c50830a9d05b7dfa83b5).
"""
function ssh_string_new(size)
    @ccall libssh.ssh_string_new(size::Csize_t)::ssh_string
end

"""
    ssh_string_get_char(str)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__string.html#gada306ef3f18485ea75041d85a43e2175).
"""
function ssh_string_get_char(str)
    @ccall libssh.ssh_string_get_char(str::ssh_string)::Ptr{Cchar}
end

"""
    ssh_string_to_char(str)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__string.html#ga1d4d4b71252e61671887edb19db47826).
"""
function ssh_string_to_char(str)
    @ccall libssh.ssh_string_to_char(str::ssh_string)::Ptr{Cchar}
end

"""
    ssh_getpass(prompt, buf, len, echo, verify)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__misc.html#gad6effc9fcc3529ae5d7301fb096aa71c).
"""
function ssh_getpass(prompt, buf, len, echo, verify)
    @ccall libssh.ssh_getpass(prompt::Ptr{Cchar}, buf::Ptr{Cchar}, len::Csize_t, echo::Cint, verify::Cint)::Cint
end

# typedef int ( * ssh_event_callback ) ( socket_t fd , int revents , void * userdata )
const ssh_event_callback = Ptr{Cvoid}

"""
    ssh_event_new()

[Upstream documentation](https://api.libssh.org/stable/group__libssh__poll.html#ga406895f99b6b486c4b65536e5399ff96).
"""
function ssh_event_new()
    @ccall libssh.ssh_event_new()::ssh_event
end

"""
    ssh_event_add_fd(event, fd, events, cb, userdata)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__poll.html#ga41d63ffe950a48e8b2c513877e0cd6b4).
"""
function ssh_event_add_fd(event, fd, events, cb, userdata)
    @ccall libssh.ssh_event_add_fd(event::ssh_event, fd::socket_t, events::Cshort, cb::ssh_event_callback, userdata::Ptr{Cvoid})::Cint
end

"""
    ssh_event_add_session(event, session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__poll.html#ga51af38de4cc3adbd5566ec1f1b91983d).
"""
function ssh_event_add_session(event, session)
    @ccall libssh.ssh_event_add_session(event::ssh_event, session::ssh_session)::Cint
end

"""
    ssh_event_add_connector(event, connector)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__poll.html#gae1f53a6ce420a41ae06ffb962f477f99).
"""
function ssh_event_add_connector(event, connector)
    @ccall libssh.ssh_event_add_connector(event::ssh_event, connector::ssh_connector)::Cint
end

"""
    ssh_event_dopoll(event, timeout)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__poll.html#gada90c0ca6919271708ba1ea0352632cb).
"""
function ssh_event_dopoll(event, timeout)
    @ccall libssh.ssh_event_dopoll(event::ssh_event, timeout::Cint)::Cint
end

"""
    ssh_event_remove_fd(event, fd)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__poll.html#gaf2cdca09a3a2024ed9bb4f134c8ae368).
"""
function ssh_event_remove_fd(event, fd)
    @ccall libssh.ssh_event_remove_fd(event::ssh_event, fd::socket_t)::Cint
end

"""
    ssh_event_remove_session(event, session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__poll.html#gaab8dec05a0afb49392c63b2ec158ac3d).
"""
function ssh_event_remove_session(event, session)
    @ccall libssh.ssh_event_remove_session(event::ssh_event, session::ssh_session)::Cint
end

"""
    ssh_event_remove_connector(event, connector)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__poll.html#gae120116df5a1da09ee9edd42e6a63397).
"""
function ssh_event_remove_connector(event, connector)
    @ccall libssh.ssh_event_remove_connector(event::ssh_event, connector::ssh_connector)::Cint
end

"""
    ssh_event_free(event)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__poll.html#ga101388903c74d53ed550574b587449cd).
"""
function ssh_event_free(event)
    @ccall libssh.ssh_event_free(event::ssh_event)::Cvoid
end

"""
    ssh_get_clientbanner(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga6b673c4ddc6fa4d75752d6b1a390c74b).
"""
function ssh_get_clientbanner(session)
    @ccall libssh.ssh_get_clientbanner(session::ssh_session)::Ptr{Cchar}
end

"""
    ssh_get_serverbanner(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga144bb84d1b1a23f3b520a42a8fc6e56a).
"""
function ssh_get_serverbanner(session)
    @ccall libssh.ssh_get_serverbanner(session::ssh_session)::Ptr{Cchar}
end

"""
    ssh_get_kex_algo(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga4c1849674102ae18d09f39899df65e39).
"""
function ssh_get_kex_algo(session)
    @ccall libssh.ssh_get_kex_algo(session::ssh_session)::Ptr{Cchar}
end

"""
    ssh_get_cipher_in(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga619f4e872874bdbeacc8a7c0f07066ef).
"""
function ssh_get_cipher_in(session)
    @ccall libssh.ssh_get_cipher_in(session::ssh_session)::Ptr{Cchar}
end

"""
    ssh_get_cipher_out(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga00499399aa92be2c4e2aa5fb5c2ac353).
"""
function ssh_get_cipher_out(session)
    @ccall libssh.ssh_get_cipher_out(session::ssh_session)::Ptr{Cchar}
end

"""
    ssh_get_hmac_in(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#ga17b0d90856562626c3198be0e164c528).
"""
function ssh_get_hmac_in(session)
    @ccall libssh.ssh_get_hmac_in(session::ssh_session)::Ptr{Cchar}
end

"""
    ssh_get_hmac_out(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gaafc999f5270e8fcadab625389ccffa18).
"""
function ssh_get_hmac_out(session)
    @ccall libssh.ssh_get_hmac_out(session::ssh_session)::Ptr{Cchar}
end

"""
    ssh_buffer_new()

[Upstream documentation](https://api.libssh.org/stable/group__libssh__buffer.html#gac0c9beff0f051a05444f531caf70bac7).
"""
function ssh_buffer_new()
    @ccall libssh.ssh_buffer_new()::ssh_buffer
end

"""
    ssh_buffer_reinit(buffer)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__buffer.html#gad877da63fd8d9a0ee00859bfbacf1eda).
"""
function ssh_buffer_reinit(buffer)
    @ccall libssh.ssh_buffer_reinit(buffer::ssh_buffer)::Cint
end

"""
    ssh_buffer_add_data(buffer, data, len)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__buffer.html#ga3bf82f0f310311432410f9393ebab528).
"""
function ssh_buffer_add_data(buffer, data, len)
    @ccall libssh.ssh_buffer_add_data(buffer::ssh_buffer, data::Ptr{Cvoid}, len::UInt32)::Cint
end

"""
    ssh_buffer_get_data(buffer, data, requestedlen)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__buffer.html#ga2664b48795a4cba70a424e7704bdbcf2).
"""
function ssh_buffer_get_data(buffer, data, requestedlen)
    @ccall libssh.ssh_buffer_get_data(buffer::ssh_buffer, data::Ptr{Cvoid}, requestedlen::UInt32)::UInt32
end

"""
    ssh_buffer_get(buffer)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__buffer.html#gabaa8d816d58aeb9749405def74ec96a4).
"""
function ssh_buffer_get(buffer)
    @ccall libssh.ssh_buffer_get(buffer::ssh_buffer)::Ptr{Cvoid}
end

"""
    ssh_buffer_get_len(buffer)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__buffer.html#gad1594908ed57799f4a84066f47c3e7c0).
"""
function ssh_buffer_get_len(buffer)
    @ccall libssh.ssh_buffer_get_len(buffer::ssh_buffer)::UInt32
end

"""
    ssh_session_set_disconnect_message(session, message)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__session.html#gab9d24979888b0b0ad217fb2071fe7f9a).
"""
function ssh_session_set_disconnect_message(session, message)
    @ccall libssh.ssh_session_set_disconnect_message(session::ssh_session, message::Ptr{Cchar})::Cint
end

mutable struct ssh_private_key_struct end

const ssh_private_key = Ptr{ssh_private_key_struct}

mutable struct ssh_public_key_struct end

const ssh_public_key = Ptr{ssh_public_key_struct}

function ssh_auth_list(session)
    @ccall libssh.ssh_auth_list(session::ssh_session)::Cint
end

function ssh_userauth_offer_pubkey(session, username, type, publickey)
    @ccall libssh.ssh_userauth_offer_pubkey(session::ssh_session, username::Ptr{Cchar}, type::Cint, publickey::ssh_string)::Cint
end

function ssh_userauth_pubkey(session, username, publickey, privatekey)
    @ccall libssh.ssh_userauth_pubkey(session::ssh_session, username::Ptr{Cchar}, publickey::ssh_string, privatekey::ssh_private_key)::Cint
end

function ssh_userauth_agent_pubkey(session, username, publickey)
    @ccall libssh.ssh_userauth_agent_pubkey(session::ssh_session, username::Ptr{Cchar}, publickey::ssh_public_key)::Cint
end

function ssh_userauth_autopubkey(session, passphrase)
    @ccall libssh.ssh_userauth_autopubkey(session::ssh_session, passphrase::Ptr{Cchar})::Cint
end

function ssh_userauth_privatekey_file(session, username, filename, passphrase)
    @ccall libssh.ssh_userauth_privatekey_file(session::ssh_session, username::Ptr{Cchar}, filename::Ptr{Cchar}, passphrase::Ptr{Cchar})::Cint
end

function buffer_free(buffer)
    @ccall libssh.buffer_free(buffer::ssh_buffer)::Cvoid
end

function buffer_get(buffer)
    @ccall libssh.buffer_get(buffer::ssh_buffer)::Ptr{Cvoid}
end

function buffer_get_len(buffer)
    @ccall libssh.buffer_get_len(buffer::ssh_buffer)::UInt32
end

function buffer_new()
    @ccall libssh.buffer_new()::ssh_buffer
end

function channel_accept_x11(channel, timeout_ms)
    @ccall libssh.channel_accept_x11(channel::ssh_channel, timeout_ms::Cint)::ssh_channel
end

function channel_change_pty_size(channel, cols, rows)
    @ccall libssh.channel_change_pty_size(channel::ssh_channel, cols::Cint, rows::Cint)::Cint
end

function channel_forward_accept(session, timeout_ms)
    @ccall libssh.channel_forward_accept(session::ssh_session, timeout_ms::Cint)::ssh_channel
end

function channel_close(channel)
    @ccall libssh.channel_close(channel::ssh_channel)::Cint
end

function channel_forward_cancel(session, address, port)
    @ccall libssh.channel_forward_cancel(session::ssh_session, address::Ptr{Cchar}, port::Cint)::Cint
end

function channel_forward_listen(session, address, port, bound_port)
    @ccall libssh.channel_forward_listen(session::ssh_session, address::Ptr{Cchar}, port::Cint, bound_port::Ptr{Cint})::Cint
end

function channel_free(channel)
    @ccall libssh.channel_free(channel::ssh_channel)::Cvoid
end

function channel_get_exit_status(channel)
    @ccall libssh.channel_get_exit_status(channel::ssh_channel)::Cint
end

function channel_get_session(channel)
    @ccall libssh.channel_get_session(channel::ssh_channel)::ssh_session
end

function channel_is_closed(channel)
    @ccall libssh.channel_is_closed(channel::ssh_channel)::Cint
end

function channel_is_eof(channel)
    @ccall libssh.channel_is_eof(channel::ssh_channel)::Cint
end

function channel_is_open(channel)
    @ccall libssh.channel_is_open(channel::ssh_channel)::Cint
end

function channel_new(session)
    @ccall libssh.channel_new(session::ssh_session)::ssh_channel
end

function channel_open_forward(channel, remotehost, remoteport, sourcehost, localport)
    @ccall libssh.channel_open_forward(channel::ssh_channel, remotehost::Ptr{Cchar}, remoteport::Cint, sourcehost::Ptr{Cchar}, localport::Cint)::Cint
end

function channel_open_session(channel)
    @ccall libssh.channel_open_session(channel::ssh_channel)::Cint
end

function channel_poll(channel, is_stderr)
    @ccall libssh.channel_poll(channel::ssh_channel, is_stderr::Cint)::Cint
end

function channel_read(channel, dest, count, is_stderr)
    @ccall libssh.channel_read(channel::ssh_channel, dest::Ptr{Cvoid}, count::UInt32, is_stderr::Cint)::Cint
end

"""
    channel_read_buffer(channel, buffer, count, is_stderr)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gab391f5c978cb1bc8df3ebd061f38e8c5).
"""
function channel_read_buffer(channel, buffer, count, is_stderr)
    @ccall libssh.channel_read_buffer(channel::ssh_channel, buffer::ssh_buffer, count::UInt32, is_stderr::Cint)::Cint
end

function channel_read_nonblocking(channel, dest, count, is_stderr)
    @ccall libssh.channel_read_nonblocking(channel::ssh_channel, dest::Ptr{Cvoid}, count::UInt32, is_stderr::Cint)::Cint
end

function channel_request_env(channel, name, value)
    @ccall libssh.channel_request_env(channel::ssh_channel, name::Ptr{Cchar}, value::Ptr{Cchar})::Cint
end

function channel_request_exec(channel, cmd)
    @ccall libssh.channel_request_exec(channel::ssh_channel, cmd::Ptr{Cchar})::Cint
end

function channel_request_pty(channel)
    @ccall libssh.channel_request_pty(channel::ssh_channel)::Cint
end

function channel_request_pty_size(channel, term, cols, rows)
    @ccall libssh.channel_request_pty_size(channel::ssh_channel, term::Ptr{Cchar}, cols::Cint, rows::Cint)::Cint
end

function channel_request_shell(channel)
    @ccall libssh.channel_request_shell(channel::ssh_channel)::Cint
end

function channel_request_send_signal(channel, signum)
    @ccall libssh.channel_request_send_signal(channel::ssh_channel, signum::Ptr{Cchar})::Cint
end

function channel_request_sftp(channel)
    @ccall libssh.channel_request_sftp(channel::ssh_channel)::Cint
end

function channel_request_subsystem(channel, subsystem)
    @ccall libssh.channel_request_subsystem(channel::ssh_channel, subsystem::Ptr{Cchar})::Cint
end

function channel_request_x11(channel, single_connection, protocol, cookie, screen_number)
    @ccall libssh.channel_request_x11(channel::ssh_channel, single_connection::Cint, protocol::Ptr{Cchar}, cookie::Ptr{Cchar}, screen_number::Cint)::Cint
end

function channel_send_eof(channel)
    @ccall libssh.channel_send_eof(channel::ssh_channel)::Cint
end

function channel_select(readchans, writechans, exceptchans, timeout)
    @ccall libssh.channel_select(readchans::Ptr{ssh_channel}, writechans::Ptr{ssh_channel}, exceptchans::Ptr{ssh_channel}, timeout::Ptr{Cvoid})::Cint
end

function channel_set_blocking(channel, blocking)
    @ccall libssh.channel_set_blocking(channel::ssh_channel, blocking::Cint)::Cvoid
end

function channel_write(channel, data, len)
    @ccall libssh.channel_write(channel::ssh_channel, data::Ptr{Cvoid}, len::UInt32)::Cint
end

function privatekey_free(prv)
    @ccall libssh.privatekey_free(prv::ssh_private_key)::Cvoid
end

function privatekey_from_file(session, filename, type, passphrase)
    @ccall libssh.privatekey_from_file(session::ssh_session, filename::Ptr{Cchar}, type::Cint, passphrase::Ptr{Cchar})::ssh_private_key
end

function publickey_free(key)
    @ccall libssh.publickey_free(key::ssh_public_key)::Cvoid
end

function ssh_publickey_to_file(session, file, pubkey, type)
    @ccall libssh.ssh_publickey_to_file(session::ssh_session, file::Ptr{Cchar}, pubkey::ssh_string, type::Cint)::Cint
end

function publickey_from_file(session, filename, type)
    @ccall libssh.publickey_from_file(session::ssh_session, filename::Ptr{Cchar}, type::Ptr{Cint})::ssh_string
end

function publickey_from_privatekey(prv)
    @ccall libssh.publickey_from_privatekey(prv::ssh_private_key)::ssh_public_key
end

function publickey_to_string(key)
    @ccall libssh.publickey_to_string(key::ssh_public_key)::ssh_string
end

function ssh_try_publickey_from_file(session, keyfile, publickey, type)
    @ccall libssh.ssh_try_publickey_from_file(session::ssh_session, keyfile::Ptr{Cchar}, publickey::Ptr{ssh_string}, type::Ptr{Cint})::Cint
end

function ssh_privatekey_type(privatekey)
    @ccall libssh.ssh_privatekey_type(privatekey::ssh_private_key)::ssh_keytypes_e
end

function ssh_get_pubkey(session)
    @ccall libssh.ssh_get_pubkey(session::ssh_session)::ssh_string
end

function ssh_message_retrieve(session, packettype)
    @ccall libssh.ssh_message_retrieve(session::ssh_session, packettype::UInt32)::ssh_message
end

function ssh_message_auth_publickey(msg)
    @ccall libssh.ssh_message_auth_publickey(msg::ssh_message)::ssh_public_key
end

function string_burn(str)
    @ccall libssh.string_burn(str::ssh_string)::Cvoid
end

function string_copy(str)
    @ccall libssh.string_copy(str::ssh_string)::ssh_string
end

function string_data(str)
    @ccall libssh.string_data(str::ssh_string)::Ptr{Cvoid}
end

function string_fill(str, data, len)
    @ccall libssh.string_fill(str::ssh_string, data::Ptr{Cvoid}, len::Csize_t)::Cint
end

function string_free(str)
    @ccall libssh.string_free(str::ssh_string)::Cvoid
end

function string_from_char(what)
    @ccall libssh.string_from_char(what::Ptr{Cchar})::ssh_string
end

function string_len(str)
    @ccall libssh.string_len(str::ssh_string)::Csize_t
end

function string_new(size)
    @ccall libssh.string_new(size::Csize_t)::ssh_string
end

function string_to_char(str)
    @ccall libssh.string_to_char(str::ssh_string)::Ptr{Cchar}
end

mutable struct sftp_aio_struct end

const sftp_aio = Ptr{sftp_aio_struct}

"""
    sftp_aio_free(aio)

Deallocate memory corresponding to a sftp aio handle.

This function deallocates memory corresponding to the aio handle returned by the sftp\\_aio\\_begin\\_*() functions. Users can use this function to free memory corresponding to an aio handle for an outstanding async i/o request on encountering some error.

# Arguments
* `aio`: sftp aio handle corresponding to which memory has to be deallocated.
# See also
[`sftp_aio_begin_read`](@ref)(), [`sftp_aio_wait_read`](@ref)(), [`sftp_aio_begin_write`](@ref)(), [`sftp_aio_wait_write`](@ref)()
"""
function sftp_aio_free(aio)
    @ccall libssh.sftp_aio_free(aio::sftp_aio)::Cvoid
end

struct sftp_attributes_struct
    name::Ptr{Cchar}
    longname::Ptr{Cchar}
    flags::UInt32
    type::UInt8
    size::UInt64
    uid::UInt32
    gid::UInt32
    owner::Ptr{Cchar}
    group::Ptr{Cchar}
    permissions::UInt32
    atime64::UInt64
    atime::UInt32
    atime_nseconds::UInt32
    createtime::UInt64
    createtime_nseconds::UInt32
    mtime64::UInt64
    mtime::UInt32
    mtime_nseconds::UInt32
    acl::ssh_string
    extended_count::UInt32
    extended_type::ssh_string
    extended_data::ssh_string
end
function Base.getproperty(x::Ptr{sftp_attributes_struct}, f::Symbol)
    f === :name && return Ptr{Ptr{Cchar}}(x + 0)
    f === :longname && return Ptr{Ptr{Cchar}}(x + 8)
    f === :flags && return Ptr{UInt32}(x + 16)
    f === :type && return Ptr{UInt8}(x + 20)
    f === :size && return Ptr{UInt64}(x + 24)
    f === :uid && return Ptr{UInt32}(x + 32)
    f === :gid && return Ptr{UInt32}(x + 36)
    f === :owner && return Ptr{Ptr{Cchar}}(x + 40)
    f === :group && return Ptr{Ptr{Cchar}}(x + 48)
    f === :permissions && return Ptr{UInt32}(x + 56)
    f === :atime64 && return Ptr{UInt64}(x + 64)
    f === :atime && return Ptr{UInt32}(x + 72)
    f === :atime_nseconds && return Ptr{UInt32}(x + 76)
    f === :createtime && return Ptr{UInt64}(x + 80)
    f === :createtime_nseconds && return Ptr{UInt32}(x + 88)
    f === :mtime64 && return Ptr{UInt64}(x + 96)
    f === :mtime && return Ptr{UInt32}(x + 104)
    f === :mtime_nseconds && return Ptr{UInt32}(x + 108)
    f === :acl && return Ptr{ssh_string}(x + 112)
    f === :extended_count && return Ptr{UInt32}(x + 120)
    f === :extended_type && return Ptr{ssh_string}(x + 128)
    f === :extended_data && return Ptr{ssh_string}(x + 136)
    return getfield(x, f)
end

function Base.setproperty!(x::Ptr{sftp_attributes_struct}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const sftp_attributes = Ptr{sftp_attributes_struct}

mutable struct __JL_sftp_request_queue_struct
end

function Base.unsafe_load(x::Ptr{__JL_sftp_request_queue_struct})
    unsafe_load(Ptr{sftp_request_queue_struct}(x))
end

function Base.getproperty(x::Ptr{__JL_sftp_request_queue_struct}, f::Symbol)
    getproperty(Ptr{sftp_request_queue_struct}(x), f)
end

function Base.setproperty!(x::Ptr{__JL_sftp_request_queue_struct}, f::Symbol, v)
    setproperty!(Ptr{sftp_request_queue_struct}(x), f, v)
end

const sftp_request_queue = Ptr{__JL_sftp_request_queue_struct}

mutable struct sftp_ext_struct end

const sftp_ext = Ptr{sftp_ext_struct}

mutable struct __JL_sftp_packet_struct
end

function Base.unsafe_load(x::Ptr{__JL_sftp_packet_struct})
    unsafe_load(Ptr{sftp_packet_struct}(x))
end

function Base.getproperty(x::Ptr{__JL_sftp_packet_struct}, f::Symbol)
    getproperty(Ptr{sftp_packet_struct}(x), f)
end

function Base.setproperty!(x::Ptr{__JL_sftp_packet_struct}, f::Symbol, v)
    setproperty!(Ptr{sftp_packet_struct}(x), f, v)
end

const sftp_packet = Ptr{__JL_sftp_packet_struct}

"""
    sftp_limits_struct

SFTP limits structure.
"""
struct sftp_limits_struct
    max_packet_length::UInt64
    max_read_length::UInt64
    max_write_length::UInt64
    max_open_handles::UInt64
end

"""
Pointer to a [`sftp_limits_struct`](@ref)
"""
const sftp_limits_t = Ptr{sftp_limits_struct}

struct sftp_session_struct
    session::ssh_session
    channel::ssh_channel
    server_version::Cint
    client_version::Cint
    version::Cint
    queue::sftp_request_queue
    id_counter::UInt32
    errnum::Cint
    handles::Ptr{Ptr{Cvoid}}
    ext::sftp_ext
    read_packet::sftp_packet
    limits::sftp_limits_t
end

const sftp_session = Ptr{sftp_session_struct}

mutable struct sftp_client_message_struct
    sftp::sftp_session
    type::UInt8
    id::UInt32
    filename::Ptr{Cchar}
    flags::UInt32
    attr::sftp_attributes
    handle::ssh_string
    offset::UInt64
    len::UInt32
    attr_num::Cint
    attrbuf::ssh_buffer
    data::ssh_string
    complete_message::ssh_buffer
    str_data::Ptr{Cchar}
    submessage::Ptr{Cchar}
end

const sftp_client_message = Ptr{sftp_client_message_struct}

mutable struct sftp_dir_struct
    sftp::sftp_session
    name::Ptr{Cchar}
    handle::ssh_string
    buffer::ssh_buffer
    count::UInt32
    eof::Cint
end

const sftp_dir = Ptr{sftp_dir_struct}

mutable struct sftp_file_struct
    sftp::sftp_session
    name::Ptr{Cchar}
    offset::UInt64
    handle::ssh_string
    eof::Cint
    nonblocking::Cint
end

const sftp_file = Ptr{sftp_file_struct}

struct sftp_message_struct
    sftp::sftp_session
    packet_type::UInt8
    payload::ssh_buffer
    id::UInt32
end

const sftp_message = Ptr{sftp_message_struct}

mutable struct sftp_status_message_struct
    id::UInt32
    status::UInt32
    error_unused::ssh_string
    lang_unused::ssh_string
    errormsg::Ptr{Cchar}
    langmsg::Ptr{Cchar}
end

const sftp_status_message = Ptr{sftp_status_message_struct}

"""
    sftp_statvfs_struct

SFTP statvfs structure.
"""
mutable struct sftp_statvfs_struct
    f_bsize::UInt64
    f_frsize::UInt64
    f_blocks::UInt64
    f_bfree::UInt64
    f_bavail::UInt64
    f_files::UInt64
    f_ffree::UInt64
    f_favail::UInt64
    f_fsid::UInt64
    f_flag::UInt64
    f_namemax::UInt64
end

const sftp_statvfs_t = Ptr{sftp_statvfs_struct}

mutable struct sftp_packet_struct
    sftp::sftp_session
    type::UInt8
    payload::ssh_buffer
end
Base.unsafe_convert(::Type{Ptr{__JL_sftp_packet_struct}}, x::Base.RefValue{sftp_packet_struct}) = Base.unsafe_convert(Ptr{__JL_sftp_packet_struct}, Base.unsafe_convert(Ptr{sftp_packet_struct}, x))

Base.unsafe_convert(::Type{Ptr{__JL_sftp_packet_struct}}, x::Ptr{sftp_packet_struct}) = Ptr{__JL_sftp_packet_struct}(x)


mutable struct sftp_request_queue_struct
    next::sftp_request_queue
    message::sftp_message
end
Base.unsafe_convert(::Type{Ptr{__JL_sftp_request_queue_struct}}, x::Base.RefValue{sftp_request_queue_struct}) = Base.unsafe_convert(Ptr{__JL_sftp_request_queue_struct}, Base.unsafe_convert(Ptr{sftp_request_queue_struct}, x))

Base.unsafe_convert(::Type{Ptr{__JL_sftp_request_queue_struct}}, x::Ptr{sftp_request_queue_struct}) = Ptr{__JL_sftp_request_queue_struct}(x)


function _threadcall_sftp_new(session::ssh_session)
    gc_state = @ccall(jl_gc_safe_enter()::Int8)
    ret = @ccall(libssh.sftp_new(session::ssh_session)::sftp_session)
    @ccall jl_gc_safe_leave(gc_state::Int8)::Cvoid
    return ret
end

"""
    sftp_new(session::ssh_session)

Auto-generated wrapper around `sftp_new()`. Original upstream documentation is below.

---

Creates a new sftp session.

This function creates a new sftp session and allocates a new sftp channel with the server inside of the provided ssh session. This function call is usually followed by the [`sftp_init`](@ref)(), which initializes SFTP protocol itself.

# Arguments
* `session`: The ssh session to use.
# Returns
A new sftp session or NULL on error.
# See also
[`sftp_free`](@ref)(), [`sftp_init`](@ref)()
"""
function sftp_new(session::ssh_session)
    cfunc = @cfunction(_threadcall_sftp_new, sftp_session, (ssh_session,))
    return @threadcall(cfunc, sftp_session, (ssh_session,), session)
end

"""
    sftp_new_channel(session, channel)

Start a new sftp session with an existing channel.

# Arguments
* `session`: The ssh session to use.
* `channel`:	An open session channel with subsystem already allocated
# Returns
A new sftp session or NULL on error.
# See also
[`sftp_free`](@ref)()
"""
function sftp_new_channel(session, channel)
    @ccall libssh.sftp_new_channel(session::ssh_session, channel::ssh_channel)::sftp_session
end

"""
    sftp_free(sftp)

Close and deallocate a sftp session.

# Arguments
* `sftp`: The sftp session handle to free.
"""
function sftp_free(sftp)
    @ccall libssh.sftp_free(sftp::sftp_session)::Cvoid
end

function _threadcall_sftp_init(sftp::sftp_session)
    gc_state = @ccall(jl_gc_safe_enter()::Int8)
    ret = @ccall(libssh.sftp_init(sftp::sftp_session)::Cint)
    @ccall jl_gc_safe_leave(gc_state::Int8)::Cvoid
    return ret
end

"""
    sftp_init(sftp::sftp_session)

Auto-generated wrapper around `sftp_init()`. Original upstream documentation is below.

---

Initialize the sftp protocol with the server.

This function involves the SFTP protocol initialization (as described in the SFTP specification), including the version and extensions negotiation.

# Arguments
* `sftp`: The sftp session to initialize.
# Returns
0 on success, < 0 on error with ssh error set.
# See also
[`sftp_new`](@ref)()
"""
function sftp_init(sftp::sftp_session)
    cfunc = @cfunction(_threadcall_sftp_init, Cint, (sftp_session,))
    return @threadcall(cfunc, Cint, (sftp_session,), sftp)
end

"""
    sftp_get_error(sftp)

Get the last sftp error.

Use this function to get the latest error set by a posix like sftp function.

# Arguments
* `sftp`: The sftp session where the error is saved.
# Returns
The saved error (see server responses), < 0 if an error in the function occurred.
# See also
Server responses
"""
function sftp_get_error(sftp)
    @ccall libssh.sftp_get_error(sftp::sftp_session)::Cint
end

"""
    sftp_extensions_get_count(sftp)

Get the count of extensions provided by the server.

# Arguments
* `sftp`: The sftp session to use.
# Returns
The count of extensions provided by the server, 0 on error or not available.
"""
function sftp_extensions_get_count(sftp)
    @ccall libssh.sftp_extensions_get_count(sftp::sftp_session)::Cuint
end

"""
    sftp_extensions_get_name(sftp, indexn; throw = true)

Auto-generated wrapper around `sftp_extensions_get_name()`. Original upstream documentation is below.

---

Get the name of the extension provided by the server.

# Arguments
* `sftp`: The sftp session to use.
* `indexn`: The index number of the extension name you want.
# Returns
The name of the extension.
"""
function sftp_extensions_get_name(sftp, indexn; throw = true)
    ret = @ccall(libssh.sftp_extensions_get_name(sftp::sftp_session, indexn::Cuint)::Ptr{Cchar})
    if ret == C_NULL
        if throw
            Base.throw(LibSSHException("Error from sftp_extensions_get_name, no string found (returned C_NULL)"))
        else
            return ret
        end
    end
    return unsafe_string(Ptr{UInt8}(ret))
end

"""
    sftp_extensions_get_data(sftp, indexn; throw = true)

Auto-generated wrapper around `sftp_extensions_get_data()`. Original upstream documentation is below.

---

Get the data of the extension provided by the server.

This is normally the version number of the extension.

# Arguments
* `sftp`: The sftp session to use.
* `indexn`: The index number of the extension data you want.
# Returns
The data of the extension.
"""
function sftp_extensions_get_data(sftp, indexn; throw = true)
    ret = @ccall(libssh.sftp_extensions_get_data(sftp::sftp_session, indexn::Cuint)::Ptr{Cchar})
    if ret == C_NULL
        if throw
            Base.throw(LibSSHException("Error from sftp_extensions_get_data, no string found (returned C_NULL)"))
        else
            return ret
        end
    end
    return unsafe_string(Ptr{UInt8}(ret))
end

"""
    sftp_extension_supported(sftp, name, data)

Check if the given extension is supported.

Example:

```c++
 sftp_extension_supported(sftp, "statvfs@openssh.com", "2");
```

# Arguments
* `sftp`: The sftp session to use.
* `name`: The name of the extension.
* `data`: The data of the extension.
# Returns
1 if supported, 0 if not.
"""
function sftp_extension_supported(sftp, name, data)
    @ccall libssh.sftp_extension_supported(sftp::sftp_session, name::Ptr{Cchar}, data::Ptr{Cchar})::Cint
end

function _threadcall_sftp_opendir(session::sftp_session, path::Ptr{Cchar})
    gc_state = @ccall(jl_gc_safe_enter()::Int8)
    ret = @ccall(libssh.sftp_opendir(session::sftp_session, path::Ptr{Cchar})::sftp_dir)
    @ccall jl_gc_safe_leave(gc_state::Int8)::Cvoid
    return ret
end

"""
    sftp_opendir(session::sftp_session, path::Ptr{Cchar})

Auto-generated wrapper around `sftp_opendir()`. Original upstream documentation is below.

---

Open a directory used to obtain directory entries.

# Arguments
* `session`: The sftp session handle to open the directory.
* `path`: The path of the directory to open.
# Returns
A sftp directory handle or NULL on error with ssh and sftp error set.
# See also
[`sftp_readdir`](@ref), [`sftp_closedir`](@ref)
"""
function sftp_opendir(session::sftp_session, path::Ptr{Cchar})
    cfunc = @cfunction(_threadcall_sftp_opendir, sftp_dir, (sftp_session, Ptr{Cchar}))
    return @threadcall(cfunc, sftp_dir, (sftp_session, Ptr{Cchar}), session, path)
end

function _threadcall_sftp_readdir(session::sftp_session, dir::sftp_dir)
    gc_state = @ccall(jl_gc_safe_enter()::Int8)
    ret = @ccall(libssh.sftp_readdir(session::sftp_session, dir::sftp_dir)::sftp_attributes)
    @ccall jl_gc_safe_leave(gc_state::Int8)::Cvoid
    return ret
end

"""
    sftp_readdir(session::sftp_session, dir::sftp_dir)

Auto-generated wrapper around `sftp_readdir()`. Original upstream documentation is below.

---

Get a single file attributes structure of a directory.

# Arguments
* `session`: The sftp session handle to read the directory entry.
* `dir`: The opened sftp directory handle to read from.
# Returns
A file attribute structure or NULL at the end of the directory.
# See also
[`sftp_opendir`](@ref)(), sftp\\_attribute\\_free(), [`sftp_closedir`](@ref)()
"""
function sftp_readdir(session::sftp_session, dir::sftp_dir)
    cfunc = @cfunction(_threadcall_sftp_readdir, sftp_attributes, (sftp_session, sftp_dir))
    return @threadcall(cfunc, sftp_attributes, (sftp_session, sftp_dir), session, dir)
end

"""
    sftp_dir_eof(dir)

Tell if the directory has reached EOF (End Of File).

# Arguments
* `dir`: The sftp directory handle.
# Returns
1 if the directory is EOF, 0 if not.
# See also
[`sftp_readdir`](@ref)()
"""
function sftp_dir_eof(dir)
    @ccall libssh.sftp_dir_eof(dir::sftp_dir)::Cint
end

function _threadcall_sftp_stat(session::sftp_session, path::Ptr{Cchar})
    gc_state = @ccall(jl_gc_safe_enter()::Int8)
    ret = @ccall(libssh.sftp_stat(session::sftp_session, path::Ptr{Cchar})::sftp_attributes)
    @ccall jl_gc_safe_leave(gc_state::Int8)::Cvoid
    return ret
end

"""
    sftp_stat(session::sftp_session, path::Ptr{Cchar})

Auto-generated wrapper around `sftp_stat()`. Original upstream documentation is below.

---

Get information about a file or directory.

# Arguments
* `session`: The sftp session handle.
* `path`: The path to the file or directory to obtain the information.
# Returns
The sftp attributes structure of the file or directory, NULL on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_stat(session::sftp_session, path::Ptr{Cchar})
    cfunc = @cfunction(_threadcall_sftp_stat, sftp_attributes, (sftp_session, Ptr{Cchar}))
    return @threadcall(cfunc, sftp_attributes, (sftp_session, Ptr{Cchar}), session, path)
end

"""
    sftp_lstat(session, path)

Get information about a file or directory.

Identical to [`sftp_stat`](@ref), but if the file or directory is a symbolic link, then the link itself is stated, not the file that it refers to.

# Arguments
* `session`: The sftp session handle.
* `path`: The path to the file or directory to obtain the information.
# Returns
The sftp attributes structure of the file or directory, NULL on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_lstat(session, path)
    @ccall libssh.sftp_lstat(session::sftp_session, path::Ptr{Cchar})::sftp_attributes
end

"""
    sftp_fstat(file)

Get information about a file or directory from a file handle.

# Arguments
* `file`: The sftp file handle to get the stat information.
# Returns
The sftp attributes structure of the file or directory, NULL on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_fstat(file)
    @ccall libssh.sftp_fstat(file::sftp_file)::sftp_attributes
end

"""
    sftp_attributes_free(file)

Free a sftp attribute structure.

# Arguments
* `file`: The sftp attribute structure to free.
"""
function sftp_attributes_free(file)
    @ccall libssh.sftp_attributes_free(file::sftp_attributes)::Cvoid
end

function _threadcall_sftp_closedir(dir::sftp_dir)
    gc_state = @ccall(jl_gc_safe_enter()::Int8)
    ret = @ccall(libssh.sftp_closedir(dir::sftp_dir)::Cint)
    @ccall jl_gc_safe_leave(gc_state::Int8)::Cvoid
    return ret
end

"""
    sftp_closedir(dir::sftp_dir)

Auto-generated wrapper around `sftp_closedir()`. Original upstream documentation is below.

---

Close a directory handle opened by [`sftp_opendir`](@ref)().

# Arguments
* `dir`: The sftp directory handle to close.
# Returns
Returns SSH\\_NO\\_ERROR or [`SSH_ERROR`](@ref) if an error occurred.
"""
function sftp_closedir(dir::sftp_dir)
    cfunc = @cfunction(_threadcall_sftp_closedir, Cint, (sftp_dir,))
    return @threadcall(cfunc, Cint, (sftp_dir,), dir)
end

function _threadcall_sftp_close(file::sftp_file)
    gc_state = @ccall(jl_gc_safe_enter()::Int8)
    ret = @ccall(libssh.sftp_close(file::sftp_file)::Cint)
    @ccall jl_gc_safe_leave(gc_state::Int8)::Cvoid
    return ret
end

"""
    sftp_close(file::sftp_file)

Auto-generated wrapper around `sftp_close()`. Original upstream documentation is below.

---

Close an open file handle.

# Arguments
* `file`: The open sftp file handle to close.
# Returns
Returns SSH\\_NO\\_ERROR or [`SSH_ERROR`](@ref) if an error occurred.
# See also
[`sftp_open`](@ref)()
"""
function sftp_close(file::sftp_file)
    cfunc = @cfunction(_threadcall_sftp_close, Cint, (sftp_file,))
    return @threadcall(cfunc, Cint, (sftp_file,), file)
end

function _threadcall_sftp_open(session::sftp_session, file::Ptr{Cchar}, accesstype::Cint, mode::mode_t)
    gc_state = @ccall(jl_gc_safe_enter()::Int8)
    ret = @ccall(libssh.sftp_open(session::sftp_session, file::Ptr{Cchar}, accesstype::Cint, mode::mode_t)::sftp_file)
    @ccall jl_gc_safe_leave(gc_state::Int8)::Cvoid
    return ret
end

"""
    sftp_open(session::sftp_session, file::Ptr{Cchar}, accesstype::Cint, mode::mode_t)

Auto-generated wrapper around `sftp_open()`. Original upstream documentation is below.

---

Open a file on the server.

# Arguments
* `session`: The sftp session handle.
* `file`: The file to be opened.
* `accesstype`: Is one of O\\_RDONLY, O\\_WRONLY or O\\_RDWR which request opening the file read-only,write-only or read/write. Acesss may also be bitwise-or'd with one or more of the following: O\\_CREAT - If the file does not exist it will be created. O\\_EXCL - When used with O\\_CREAT, if the file already exists it is an error and the open will fail. O\\_TRUNC - If the file already exists it will be truncated.
* `mode`: Mode specifies the permissions to use if a new file is created. It is modified by the process's umask in the usual way: The permissions of the created file are (mode & ~umask)
# Returns
A sftp file handle, NULL on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_open(session::sftp_session, file::Ptr{Cchar}, accesstype::Cint, mode::mode_t)
    cfunc = @cfunction(_threadcall_sftp_open, sftp_file, (sftp_session, Ptr{Cchar}, Cint, mode_t))
    return @threadcall(cfunc, sftp_file, (sftp_session, Ptr{Cchar}, Cint, mode_t), session, file, accesstype, mode)
end

"""
    sftp_file_set_nonblocking(handle)

Make the sftp communication for this file handle non blocking.

# Arguments
* `handle`:\\[in\\] The file handle to set non blocking.
"""
function sftp_file_set_nonblocking(handle)
    @ccall libssh.sftp_file_set_nonblocking(handle::sftp_file)::Cvoid
end

"""
    sftp_file_set_blocking(handle)

Make the sftp communication for this file handle blocking.

# Arguments
* `handle`:\\[in\\] The file handle to set blocking.
"""
function sftp_file_set_blocking(handle)
    @ccall libssh.sftp_file_set_blocking(handle::sftp_file)::Cvoid
end

"""
    sftp_read(file, buf, count)

Read from a file using an opened sftp file handle.

This function caps the length a user is allowed to read from an sftp file.

The value used for the cap is same as the value of the max\\_read\\_length field of the [`sftp_limits_t`](@ref) returned by [`sftp_limits`](@ref)().

# Arguments
* `file`: The opened sftp file handle to be read from.
* `buf`: Pointer to buffer to receive read data.
* `count`: Size of the buffer in bytes.
# Returns
Number of bytes read, < 0 on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_read(file, buf, count)
    @ccall libssh.sftp_read(file::sftp_file, buf::Ptr{Cvoid}, count::Csize_t)::Cssize_t
end

"""
    sftp_async_read_begin(file, len)

Start an asynchronous read from a file using an opened sftp file handle.

Its goal is to avoid the slowdowns related to the request/response pattern of a synchronous read. To do so, you must call 2 functions:

[`sftp_async_read_begin`](@ref)() and [`sftp_async_read`](@ref)().

The first step is to call [`sftp_async_read_begin`](@ref)(). This function returns a request identifier. The second step is to call [`sftp_async_read`](@ref)() using the returned identifier.

!!! warning

    When calling this function, the internal offset is updated corresponding to the len parameter.

!!! warning

    A call to [`sftp_async_read_begin`](@ref)() sends a request to the server. When the server answers, libssh allocates memory to store it until [`sftp_async_read`](@ref)() is called. Not calling [`sftp_async_read`](@ref)() will lead to memory leaks.

# Arguments
* `file`: The opened sftp file handle to be read from.
* `len`: Size to read in bytes.
# Returns
An identifier corresponding to the sent request, < 0 on error.
# See also
[`sftp_async_read`](@ref)(), [`sftp_open`](@ref)()
"""
function sftp_async_read_begin(file, len)
    @ccall libssh.sftp_async_read_begin(file::sftp_file, len::UInt32)::Cint
end

"""
    sftp_async_read(file, data, len, id)

Wait for an asynchronous read to complete and save the data.

!!! warning

    A call to this function with an invalid identifier will never return.

# Arguments
* `file`: The opened sftp file handle to be read from.
* `data`: Pointer to buffer to receive read data.
* `len`: Size of the buffer in bytes. It should be bigger or equal to the length parameter of the [`sftp_async_read_begin`](@ref)() call.
* `id`: The identifier returned by the [`sftp_async_read_begin`](@ref)() function.
# Returns
Number of bytes read, 0 on EOF, [`SSH_ERROR`](@ref) if an error occurred, [`SSH_AGAIN`](@ref) if the file is opened in nonblocking mode and the request hasn't been executed yet.
# See also
[`sftp_async_read_begin`](@ref)()
"""
function sftp_async_read(file, data, len, id)
    @ccall libssh.sftp_async_read(file::sftp_file, data::Ptr{Cvoid}, len::UInt32, id::UInt32)::Cint
end

"""
    sftp_write(file, buf, count)

Write to a file using an opened sftp file handle.

This function caps the length a user is allowed to write to an sftp file.

The value used for the cap is same as the value of the max\\_write\\_length field of the [`sftp_limits_t`](@ref) returned by [`sftp_limits`](@ref)().

# Arguments
* `file`: Open sftp file handle to write to.
* `buf`: Pointer to buffer to write data.
* `count`: Size of buffer in bytes.
# Returns
Number of bytes written, < 0 on error with ssh and sftp error set.
# See also
[`sftp_open`](@ref)(), [`sftp_read`](@ref)(), [`sftp_close`](@ref)()
"""
function sftp_write(file, buf, count)
    @ccall libssh.sftp_write(file::sftp_file, buf::Ptr{Cvoid}, count::Csize_t)::Cssize_t
end

"""
    sftp_aio_begin_read(file, len, aio)

Start an asynchronous read from a file using an opened sftp file handle.

Its goal is to avoid the slowdowns related to the request/response pattern of a synchronous read. To do so, you must call 2 functions :

[`sftp_aio_begin_read`](@ref)() and [`sftp_aio_wait_read`](@ref)().

- The first step is to call [`sftp_aio_begin_read`](@ref)(). This function sends a read request to the sftp server, dynamically allocates memory to store information about the sent request and provides the caller an sftp aio handle to that memory.

- The second step is to call [`sftp_aio_wait_read`](@ref)() and pass it the address of a location storing the sftp aio handle provided by [`sftp_aio_begin_read`](@ref)().

These two functions do not close the open sftp file handle passed to [`sftp_aio_begin_read`](@ref)() irrespective of whether they fail or not.

It is the responsibility of the caller to ensure that the open sftp file handle passed to [`sftp_aio_begin_read`](@ref)() must not be closed before the corresponding call to [`sftp_aio_wait_read`](@ref)(). After [`sftp_aio_wait_read`](@ref)() returns, it is caller's decision whether to immediately close the file by calling [`sftp_close`](@ref)() or to keep it open and perform some more operations on it.

This function caps the length a user is allowed to read from an sftp file, the value of len parameter after capping is returned on success.

The value used for the cap is same as the value of the max\\_read\\_length field of the [`sftp_limits_t`](@ref) returned by [`sftp_limits`](@ref)().

!!! warning

    When calling this function, the internal file offset is updated corresponding to the number of bytes requested to read.

!!! warning

    A call to [`sftp_aio_begin_read`](@ref)() sends a request to the server. When the server answers, libssh allocates memory to store it until [`sftp_aio_wait_read`](@ref)() is called. Not calling [`sftp_aio_wait_read`](@ref)() will lead to memory leaks.

# Arguments
* `file`: The opened sftp file handle to be read from.
* `len`: Number of bytes to read.
* `aio`: Pointer to a location where the sftp aio handle (corresponding to the sent request) should be stored.
# Returns
On success, the number of bytes the server is requested to read (value of len parameter after capping). On error, [`SSH_ERROR`](@ref) with sftp and ssh errors set.
# See also
[`sftp_aio_wait_read`](@ref)(), [`sftp_aio_free`](@ref)(), [`sftp_open`](@ref)(), [`sftp_close`](@ref)(), [`sftp_get_error`](@ref)(), [`ssh_get_error`](@ref)()
"""
function sftp_aio_begin_read(file, len, aio)
    @ccall libssh.sftp_aio_begin_read(file::sftp_file, len::Csize_t, aio::Ptr{sftp_aio})::Cssize_t
end

function _threadcall_sftp_aio_wait_read(aio::Ptr{sftp_aio}, buf::Ptr{Cvoid}, buf_size::Csize_t)
    gc_state = @ccall(jl_gc_safe_enter()::Int8)
    ret = @ccall(libssh.sftp_aio_wait_read(aio::Ptr{sftp_aio}, buf::Ptr{Cvoid}, buf_size::Csize_t)::Cssize_t)
    @ccall jl_gc_safe_leave(gc_state::Int8)::Cvoid
    return ret
end

"""
    sftp_aio_wait_read(aio::Ptr{sftp_aio}, buf::Ptr{Cvoid}, buf_size::Csize_t)

Auto-generated wrapper around `sftp_aio_wait_read()`. Original upstream documentation is below.

---

Wait for an asynchronous read to complete and store the read data in the supplied buffer.

A pointer to an sftp aio handle should be passed while calling this function. Except when the return value is [`SSH_AGAIN`](@ref), this function releases the memory corresponding to the supplied aio handle and assigns NULL to that aio handle using the passed pointer to that handle.

If the file is opened in non-blocking mode and the request hasn't been executed yet, this function returns [`SSH_AGAIN`](@ref) and must be called again using the same sftp aio handle.

!!! warning

    A call to this function with an invalid sftp aio handle may never return.

# Arguments
* `aio`: Pointer to the sftp aio handle returned by [`sftp_aio_begin_read`](@ref)().
* `buf`: Pointer to the buffer in which read data will be stored.
* `buf_size`: Size of the buffer in bytes. It should be bigger or equal to the length parameter of the [`sftp_aio_begin_read`](@ref)() call.
# Returns
Number of bytes read, 0 on EOF, [`SSH_ERROR`](@ref) if an error occurred, [`SSH_AGAIN`](@ref) if the file is opened in nonblocking mode and the request hasn't been executed yet.
# See also
[`sftp_aio_begin_read`](@ref)(), [`sftp_aio_free`](@ref)()
"""
function sftp_aio_wait_read(aio::Ptr{sftp_aio}, buf::Ptr{Cvoid}, buf_size::Csize_t)
    cfunc = @cfunction(_threadcall_sftp_aio_wait_read, Cssize_t, (Ptr{sftp_aio}, Ptr{Cvoid}, Csize_t))
    return @threadcall(cfunc, Cssize_t, (Ptr{sftp_aio}, Ptr{Cvoid}, Csize_t), aio, buf, buf_size)
end

"""
    sftp_aio_begin_write(file, buf, len, aio)

Start an asynchronous write to a file using an opened sftp file handle.

Its goal is to avoid the slowdowns related to the request/response pattern of a synchronous write. To do so, you must call 2 functions :

[`sftp_aio_begin_write`](@ref)() and [`sftp_aio_wait_write`](@ref)().

- The first step is to call [`sftp_aio_begin_write`](@ref)(). This function sends a write request to the sftp server, dynamically allocates memory to store information about the sent request and provides the caller an sftp aio handle to that memory.

- The second step is to call [`sftp_aio_wait_write`](@ref)() and pass it the address of a location storing the sftp aio handle provided by [`sftp_aio_begin_write`](@ref)().

These two functions do not close the open sftp file handle passed to [`sftp_aio_begin_write`](@ref)() irrespective of whether they fail or not.

It is the responsibility of the caller to ensure that the open sftp file handle passed to [`sftp_aio_begin_write`](@ref)() must not be closed before the corresponding call to [`sftp_aio_wait_write`](@ref)(). After [`sftp_aio_wait_write`](@ref)() returns, it is caller's decision whether to immediately close the file by calling [`sftp_close`](@ref)() or to keep it open and perform some more operations on it.

This function caps the length a user is allowed to write to an sftp file, the value of len parameter after capping is returned on success.

The value used for the cap is same as the value of the max\\_write\\_length field of the [`sftp_limits_t`](@ref) returned by [`sftp_limits`](@ref)().

!!! warning

    When calling this function, the internal file offset is updated corresponding to the number of bytes requested to write.

!!! warning

    A call to [`sftp_aio_begin_write`](@ref)() sends a request to the server. When the server answers, libssh allocates memory to store it until [`sftp_aio_wait_write`](@ref)() is called. Not calling [`sftp_aio_wait_write`](@ref)() will lead to memory leaks.

# Arguments
* `file`: The opened sftp file handle to write to.
* `buf`: Pointer to the buffer containing data to write.
* `len`: Number of bytes to write.
* `aio`: Pointer to a location where the sftp aio handle (corresponding to the sent request) should be stored.
# Returns
On success, the number of bytes the server is requested to write (value of len parameter after capping). On error, [`SSH_ERROR`](@ref) with sftp and ssh errors set.
# See also
[`sftp_aio_wait_write`](@ref)(), [`sftp_aio_free`](@ref)(), [`sftp_open`](@ref)(), [`sftp_close`](@ref)(), [`sftp_get_error`](@ref)(), [`ssh_get_error`](@ref)()
"""
function sftp_aio_begin_write(file, buf, len, aio)
    @ccall libssh.sftp_aio_begin_write(file::sftp_file, buf::Ptr{Cvoid}, len::Csize_t, aio::Ptr{sftp_aio})::Cssize_t
end

function _threadcall_sftp_aio_wait_write(aio::Ptr{sftp_aio})
    gc_state = @ccall(jl_gc_safe_enter()::Int8)
    ret = @ccall(libssh.sftp_aio_wait_write(aio::Ptr{sftp_aio})::Cssize_t)
    @ccall jl_gc_safe_leave(gc_state::Int8)::Cvoid
    return ret
end

"""
    sftp_aio_wait_write(aio::Ptr{sftp_aio})

Auto-generated wrapper around `sftp_aio_wait_write()`. Original upstream documentation is below.

---

Wait for an asynchronous write to complete.

A pointer to an sftp aio handle should be passed while calling this function. Except when the return value is [`SSH_AGAIN`](@ref), this function releases the memory corresponding to the supplied aio handle and assigns NULL to that aio handle using the passed pointer to that handle.

If the file is opened in non-blocking mode and the request hasn't been executed yet, this function returns [`SSH_AGAIN`](@ref) and must be called again using the same sftp aio handle.

!!! warning

    A call to this function with an invalid sftp aio handle may never return.

# Arguments
* `aio`: Pointer to the sftp aio handle returned by [`sftp_aio_begin_write`](@ref)().
# Returns
Number of bytes written on success, [`SSH_ERROR`](@ref) if an error occurred, [`SSH_AGAIN`](@ref) if the file is opened in nonblocking mode and the request hasn't been executed yet.
# See also
[`sftp_aio_begin_write`](@ref)(), [`sftp_aio_free`](@ref)()
"""
function sftp_aio_wait_write(aio::Ptr{sftp_aio})
    cfunc = @cfunction(_threadcall_sftp_aio_wait_write, Cssize_t, (Ptr{sftp_aio},))
    return @threadcall(cfunc, Cssize_t, (Ptr{sftp_aio},), aio)
end

"""
    sftp_seek(file, new_offset)

Seek to a specific location in a file.

# Arguments
* `file`: Open sftp file handle to seek in.
* `new_offset`: Offset in bytes to seek.
# Returns
0 on success, < 0 on error.
"""
function sftp_seek(file, new_offset)
    @ccall libssh.sftp_seek(file::sftp_file, new_offset::UInt32)::Cint
end

"""
    sftp_seek64(file, new_offset)

Seek to a specific location in a file. This is the 64bit version.

# Arguments
* `file`: Open sftp file handle to seek in.
* `new_offset`: Offset in bytes to seek.
# Returns
0 on success, < 0 on error.
"""
function sftp_seek64(file, new_offset)
    @ccall libssh.sftp_seek64(file::sftp_file, new_offset::UInt64)::Cint
end

"""
    sftp_tell(file)

Report current byte position in file.

# Arguments
* `file`: Open sftp file handle.
# Returns
The offset of the current byte relative to the beginning of the file associated with the file descriptor. < 0 on error.
"""
function sftp_tell(file)
    @ccall libssh.sftp_tell(file::sftp_file)::Culong
end

"""
    sftp_tell64(file)

Report current byte position in file.

# Arguments
* `file`: Open sftp file handle.
# Returns
The offset of the current byte relative to the beginning of the file associated with the file descriptor.
"""
function sftp_tell64(file)
    @ccall libssh.sftp_tell64(file::sftp_file)::UInt64
end

"""
    sftp_rewind(file)

Rewinds the position of the file pointer to the beginning of the file.

# Arguments
* `file`: Open sftp file handle.
"""
function sftp_rewind(file)
    @ccall libssh.sftp_rewind(file::sftp_file)::Cvoid
end

"""
    sftp_unlink(sftp, file)

Unlink (delete) a file.

# Arguments
* `sftp`: The sftp session handle.
* `file`: The file to unlink/delete.
# Returns
0 on success, < 0 on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_unlink(sftp, file)
    @ccall libssh.sftp_unlink(sftp::sftp_session, file::Ptr{Cchar})::Cint
end

"""
    sftp_rmdir(sftp, directory)

Remove a directory.

# Arguments
* `sftp`: The sftp session handle.
* `directory`: The directory to remove.
# Returns
0 on success, < 0 on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_rmdir(sftp, directory)
    @ccall libssh.sftp_rmdir(sftp::sftp_session, directory::Ptr{Cchar})::Cint
end

"""
    sftp_mkdir(sftp, directory, mode)

Create a directory.

# Arguments
* `sftp`: The sftp session handle.
* `directory`: The directory to create.
* `mode`: Specifies the permissions to use. It is modified by the process's umask in the usual way: The permissions of the created file are (mode & ~umask)
# Returns
0 on success, < 0 on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_mkdir(sftp, directory, mode)
    @ccall libssh.sftp_mkdir(sftp::sftp_session, directory::Ptr{Cchar}, mode::mode_t)::Cint
end

"""
    sftp_rename(sftp, original, newname)

Rename or move a file or directory.

# Arguments
* `sftp`: The sftp session handle.
* `original`: The original url (source url) of file or directory to be moved.
* `newname`: The new url (destination url) of the file or directory after the move.
# Returns
0 on success, < 0 on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_rename(sftp, original, newname)
    @ccall libssh.sftp_rename(sftp::sftp_session, original::Ptr{Cchar}, newname::Ptr{Cchar})::Cint
end

"""
    sftp_setstat(sftp, file, attr)

Set file attributes on a file, directory or symbolic link.

Note, that this function can only set time values using 32 bit values due to the restrictions in the SFTP protocol version 3 implemented by libssh. The support for 64 bit time values was introduced in SFTP version 5, which is not implemented by libssh nor any major SFTP servers.

# Arguments
* `sftp`: The sftp session handle.
* `file`: The file which attributes should be changed.
* `attr`: The file attributes structure with the attributes set which should be changed.
# Returns
0 on success, < 0 on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_setstat(sftp, file, attr)
    @ccall libssh.sftp_setstat(sftp::sftp_session, file::Ptr{Cchar}, attr::sftp_attributes)::Cint
end

"""
    sftp_lsetstat(sftp, file, attr)

This request is like setstat (excluding mode and size) but sets file attributes on symlinks themselves.

Note, that this function can only set time values using 32 bit values due to the restrictions in the SFTP protocol version 3 implemented by libssh. The support for 64 bit time values was introduced in SFTP version 5, which is not implemented by libssh nor any major SFTP servers.

# Arguments
* `sftp`: The sftp session handle.
* `file`: The symbolic link which attributes should be changed.
* `attr`: The file attributes structure with the attributes set which should be changed.
# Returns
0 on success, < 0 on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_lsetstat(sftp, file, attr)
    @ccall libssh.sftp_lsetstat(sftp::sftp_session, file::Ptr{Cchar}, attr::sftp_attributes)::Cint
end

"""
    sftp_chown(sftp, file, owner, group)

Change the file owner and group

# Arguments
* `sftp`: The sftp session handle.
* `file`: The file which owner and group should be changed.
* `owner`: The new owner which should be set.
* `group`: The new group which should be set.
# Returns
0 on success, < 0 on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_chown(sftp, file, owner, group)
    @ccall libssh.sftp_chown(sftp::sftp_session, file::Ptr{Cchar}, owner::uid_t, group::gid_t)::Cint
end

"""
    sftp_chmod(sftp, file, mode)

Change permissions of a file

# Arguments
* `sftp`: The sftp session handle.
* `file`: The file which owner and group should be changed.
* `mode`: Specifies the permissions to use. It is modified by the process's umask in the usual way: The permissions of the created file are (mode & ~umask)
# Returns
0 on success, < 0 on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_chmod(sftp, file, mode)
    @ccall libssh.sftp_chmod(sftp::sftp_session, file::Ptr{Cchar}, mode::mode_t)::Cint
end

"""
    sftp_utimes(sftp, file, times)

Change the last modification and access time of a file.

# Arguments
* `sftp`: The sftp session handle.
* `file`: The file which owner and group should be changed.
* `times`: A timeval structure which contains the desired access and modification time.
# Returns
0 on success, < 0 on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_utimes(sftp, file, times)
    @ccall libssh.sftp_utimes(sftp::sftp_session, file::Ptr{Cchar}, times::Ptr{Cvoid})::Cint
end

"""
    sftp_symlink(sftp, target, dest)

Create a symbolic link.

# Arguments
* `sftp`: The sftp session handle.
* `target`: Specifies the target of the symlink.
* `dest`: Specifies the path name of the symlink to be created.
# Returns
0 on success, < 0 on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_symlink(sftp, target, dest)
    @ccall libssh.sftp_symlink(sftp::sftp_session, target::Ptr{Cchar}, dest::Ptr{Cchar})::Cint
end

"""
    sftp_readlink(sftp, path)

Read the value of a symbolic link.

# Arguments
* `sftp`: The sftp session handle.
* `path`: Specifies the path name of the symlink to be read.
# Returns
The target of the link, NULL on error. The caller needs to free the memory using [`ssh_string_free_char`](@ref)().
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_readlink(sftp, path)
    @ccall libssh.sftp_readlink(sftp::sftp_session, path::Ptr{Cchar})::Ptr{Cchar}
end

"""
    sftp_hardlink(sftp, oldpath, newpath)

Create a hard link.

# Arguments
* `sftp`: The sftp session handle.
* `oldpath`: Specifies the pathname of the file for which the new hardlink is to be created.
* `newpath`: Specifies the pathname of the hardlink to be created.
# Returns
0 on success, -1 on error with ssh and sftp error set.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_hardlink(sftp, oldpath, newpath)
    @ccall libssh.sftp_hardlink(sftp::sftp_session, oldpath::Ptr{Cchar}, newpath::Ptr{Cchar})::Cint
end

"""
    sftp_statvfs(sftp, path)

Get information about a mounted file system.

# Arguments
* `sftp`: The sftp session handle.
* `path`: The pathname of any file within the mounted file system.
# Returns
A statvfs structure or NULL on error.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_statvfs(sftp, path)
    @ccall libssh.sftp_statvfs(sftp::sftp_session, path::Ptr{Cchar})::sftp_statvfs_t
end

"""
    sftp_fstatvfs(file)

Get information about a mounted file system.

# Arguments
* `file`: An opened file.
# Returns
A statvfs structure or NULL on error.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_fstatvfs(file)
    @ccall libssh.sftp_fstatvfs(file::sftp_file)::sftp_statvfs_t
end

"""
    sftp_statvfs_free(statvfs_o)

Free the memory of an allocated statvfs.

# Arguments
* `statvfs_o`: The statvfs to free.
"""
function sftp_statvfs_free(statvfs_o)
    @ccall libssh.sftp_statvfs_free(statvfs_o::sftp_statvfs_t)::Cvoid
end

"""
    sftp_fsync(file)

Synchronize a file's in-core state with storage device

This calls the "fsync@openssh.com" extension. You should check if the extensions is supported using:

```c++
 int supported = sftp_extension_supported(sftp, "fsync@openssh.com", "1");
```

# Arguments
* `file`: The opened sftp file handle to sync
# Returns
0 on success, < 0 on error with ssh and sftp error set.
"""
function sftp_fsync(file)
    @ccall libssh.sftp_fsync(file::sftp_file)::Cint
end

"""
    sftp_limits(sftp)

Get information about the various limits the server might impose.

# Arguments
* `sftp`: The sftp session handle.
# Returns
A limits structure or NULL on error.
# See also
[`sftp_get_error`](@ref)()
"""
function sftp_limits(sftp)
    @ccall libssh.sftp_limits(sftp::sftp_session)::sftp_limits_t
end

"""
    sftp_limits_free(limits)

Free the memory of an allocated limits.

# Arguments
* `limits`: The limits to free.
"""
function sftp_limits_free(limits)
    @ccall libssh.sftp_limits_free(limits::sftp_limits_t)::Cvoid
end

"""
    sftp_canonicalize_path(sftp, path)

Canonicalize a sftp path.

# Arguments
* `sftp`: The sftp session handle.
* `path`: The path to be canonicalized.
# Returns
A pointer to the newly allocated canonicalized path, NULL on error. The caller needs to free the memory using [`ssh_string_free_char`](@ref)().
"""
function sftp_canonicalize_path(sftp, path)
    @ccall libssh.sftp_canonicalize_path(sftp::sftp_session, path::Ptr{Cchar})::Ptr{Cchar}
end

"""
    sftp_server_version(sftp)

Get the version of the SFTP protocol supported by the server

# Arguments
* `sftp`: The sftp session handle.
# Returns
The server version.
"""
function sftp_server_version(sftp)
    @ccall libssh.sftp_server_version(sftp::sftp_session)::Cint
end

"""
    sftp_expand_path(sftp, path)

Canonicalize path using expand-path.com extension

# Arguments
* `sftp`: The sftp session handle.
* `path`: The path to be canonicalized.
# Returns
A pointer to the newly allocated canonicalized path, NULL on error. The caller needs to free the memory using [`ssh_string_free_char`](@ref)().
"""
function sftp_expand_path(sftp, path)
    @ccall libssh.sftp_expand_path(sftp::sftp_session, path::Ptr{Cchar})::Ptr{Cchar}
end

function _threadcall_sftp_home_directory(sftp::sftp_session, username::Ptr{Cchar})
    gc_state = @ccall(jl_gc_safe_enter()::Int8)
    ret = @ccall(libssh.sftp_home_directory(sftp::sftp_session, username::Ptr{Cchar})::Ptr{Cchar})
    @ccall jl_gc_safe_leave(gc_state::Int8)::Cvoid
    return ret
end

"""
    sftp_home_directory(sftp::sftp_session, username::Ptr{Cchar})

Auto-generated wrapper around `sftp_home_directory()`. Original upstream documentation is below.

---

Get the specified user's home directory

This calls the "home-directory" extension. You should check if the extension is supported using:

```c++
 int supported  = sftp_extension_supported(sftp, "home-directory", "1");
```

# Arguments
* `sftp`: The sftp session handle.
* `username`: username of the user whose home directory is requested.
# Returns
On success, a newly allocated string containing the absolute real-path of the home directory of the user. NULL on error. The caller needs to free the memory using [`ssh_string_free_char`](@ref)().
"""
function sftp_home_directory(sftp::sftp_session, username::Ptr{Cchar})
    cfunc = @cfunction(_threadcall_sftp_home_directory, Ptr{Cchar}, (sftp_session, Ptr{Cchar}))
    return @threadcall(cfunc, Ptr{Cchar}, (sftp_session, Ptr{Cchar}), sftp, username)
end

"""
    sftp_server_new(session, chan)

Create a new sftp server session.

# Arguments
* `session`: The ssh session to use.
* `chan`: The ssh channel to use.
# Returns
A new sftp server session.
"""
function sftp_server_new(session, chan)
    @ccall libssh.sftp_server_new(session::ssh_session, chan::ssh_channel)::sftp_session
end

"""
    sftp_server_init(sftp)

Initialize the sftp server.

# Arguments
* `sftp`: The sftp session to init.
# Returns
0 on success, < 0 on error.
"""
function sftp_server_init(sftp)
    @ccall libssh.sftp_server_init(sftp::sftp_session)::Cint
end

"""
    sftp_server_free(sftp)

Close and deallocate a sftp server session.

# Arguments
* `sftp`: The sftp session handle to free.
"""
function sftp_server_free(sftp)
    @ccall libssh.sftp_server_free(sftp::sftp_session)::Cvoid
end

function sftp_get_client_message(sftp)
    @ccall libssh.sftp_get_client_message(sftp::sftp_session)::sftp_client_message
end

function sftp_client_message_free(msg)
    @ccall libssh.sftp_client_message_free(msg::sftp_client_message)::Cvoid
end

function sftp_client_message_get_type(msg)
    @ccall libssh.sftp_client_message_get_type(msg::sftp_client_message)::UInt8
end

function sftp_client_message_get_filename(msg)
    @ccall libssh.sftp_client_message_get_filename(msg::sftp_client_message)::Ptr{Cchar}
end

function sftp_client_message_set_filename(msg, newname)
    @ccall libssh.sftp_client_message_set_filename(msg::sftp_client_message, newname::Ptr{Cchar})::Cvoid
end

function sftp_client_message_get_data(msg)
    @ccall libssh.sftp_client_message_get_data(msg::sftp_client_message)::Ptr{Cchar}
end

function sftp_client_message_get_flags(msg)
    @ccall libssh.sftp_client_message_get_flags(msg::sftp_client_message)::UInt32
end

function sftp_client_message_get_submessage(msg)
    @ccall libssh.sftp_client_message_get_submessage(msg::sftp_client_message)::Ptr{Cchar}
end

function sftp_send_client_message(sftp, msg)
    @ccall libssh.sftp_send_client_message(sftp::sftp_session, msg::sftp_client_message)::Cint
end

function sftp_reply_name(msg, name, attr)
    @ccall libssh.sftp_reply_name(msg::sftp_client_message, name::Ptr{Cchar}, attr::sftp_attributes)::Cint
end

function sftp_reply_handle(msg, handle)
    @ccall libssh.sftp_reply_handle(msg::sftp_client_message, handle::ssh_string)::Cint
end

function sftp_handle_alloc(sftp, info)
    @ccall libssh.sftp_handle_alloc(sftp::sftp_session, info::Ptr{Cvoid})::ssh_string
end

function sftp_reply_attr(msg, attr)
    @ccall libssh.sftp_reply_attr(msg::sftp_client_message, attr::sftp_attributes)::Cint
end

function sftp_handle(sftp, handle)
    @ccall libssh.sftp_handle(sftp::sftp_session, handle::ssh_string)::Ptr{Cvoid}
end

function sftp_reply_status(msg, status, message)
    @ccall libssh.sftp_reply_status(msg::sftp_client_message, status::UInt32, message::Ptr{Cchar})::Cint
end

function sftp_reply_names_add(msg, file, longname, attr)
    @ccall libssh.sftp_reply_names_add(msg::sftp_client_message, file::Ptr{Cchar}, longname::Ptr{Cchar}, attr::sftp_attributes)::Cint
end

function sftp_reply_names(msg)
    @ccall libssh.sftp_reply_names(msg::sftp_client_message)::Cint
end

function sftp_reply_data(msg, data, len)
    @ccall libssh.sftp_reply_data(msg::sftp_client_message, data::Ptr{Cvoid}, len::Cint)::Cint
end

function sftp_handle_remove(sftp, handle)
    @ccall libssh.sftp_handle_remove(sftp::sftp_session, handle::Ptr{Cvoid})::Cvoid
end

@cenum ssh_bind_options_e::UInt32 begin
    SSH_BIND_OPTIONS_BINDADDR = 0
    SSH_BIND_OPTIONS_BINDPORT = 1
    SSH_BIND_OPTIONS_BINDPORT_STR = 2
    SSH_BIND_OPTIONS_HOSTKEY = 3
    SSH_BIND_OPTIONS_DSAKEY = 4
    SSH_BIND_OPTIONS_RSAKEY = 5
    SSH_BIND_OPTIONS_BANNER = 6
    SSH_BIND_OPTIONS_LOG_VERBOSITY = 7
    SSH_BIND_OPTIONS_LOG_VERBOSITY_STR = 8
    SSH_BIND_OPTIONS_ECDSAKEY = 9
    SSH_BIND_OPTIONS_IMPORT_KEY = 10
    SSH_BIND_OPTIONS_KEY_EXCHANGE = 11
    SSH_BIND_OPTIONS_CIPHERS_C_S = 12
    SSH_BIND_OPTIONS_CIPHERS_S_C = 13
    SSH_BIND_OPTIONS_HMAC_C_S = 14
    SSH_BIND_OPTIONS_HMAC_S_C = 15
    SSH_BIND_OPTIONS_CONFIG_DIR = 16
    SSH_BIND_OPTIONS_PUBKEY_ACCEPTED_KEY_TYPES = 17
    SSH_BIND_OPTIONS_HOSTKEY_ALGORITHMS = 18
    SSH_BIND_OPTIONS_PROCESS_CONFIG = 19
    SSH_BIND_OPTIONS_MODULI = 20
    SSH_BIND_OPTIONS_RSA_MIN_SIZE = 21
    SSH_BIND_OPTIONS_IMPORT_KEY_STR = 22
end

mutable struct ssh_bind_struct end

"""
[Server struct](https://api.libssh.org/stable/group__libssh__server.html)
"""
const ssh_bind = Ptr{ssh_bind_struct}

# typedef void ( * ssh_bind_incoming_connection_callback ) ( ssh_bind sshbind , void * userdata )
"""
Incoming connection callback. This callback is called when a [`ssh_bind`](@ref) has a new incoming connection.

# Arguments
* `sshbind`: Current sshbind session handler
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_bind_incoming_connection_callback = Ptr{Cvoid}

"""
    ssh_bind_callbacks_struct

These are the callbacks exported by the [`ssh_bind`](@ref) structure.

They are called by the server module when events appear on the network.
"""
mutable struct ssh_bind_callbacks_struct
    size::Csize_t
    incoming_connection::ssh_bind_incoming_connection_callback
end

"""
Callbacks for a [`ssh_bind`](@ref) ([upstream documentation](https://api.libssh.org/stable/group__libssh__server.html)).
"""
const ssh_bind_callbacks = Ptr{ssh_bind_callbacks_struct}

"""
    ssh_bind_new()

Creates a new SSH server bind.

# Returns
A newly allocated [`ssh_bind`](@ref) session pointer.
"""
function ssh_bind_new()
    @ccall libssh.ssh_bind_new()::ssh_bind
end

"""
    ssh_bind_options_set(sshbind, type, value)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__server.html#ga8fd4253643bc9cf33d6f41d170e83fff).
"""
function ssh_bind_options_set(sshbind, type, value)
    @ccall libssh.ssh_bind_options_set(sshbind::ssh_bind, type::ssh_bind_options_e, value::Ptr{Cvoid})::Cint
end

"""
    ssh_bind_options_parse_config(sshbind, filename)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__server.html#gae66c1ffe0e35b70cf88f5b8b05ed1bd6).
"""
function ssh_bind_options_parse_config(sshbind, filename)
    @ccall libssh.ssh_bind_options_parse_config(sshbind::ssh_bind, filename::Ptr{Cchar})::Cint
end

"""
    ssh_bind_listen(ssh_bind_o)

Start listening to the socket.

# Arguments
* `ssh_bind_o`: The ssh server bind to use.
# Returns
0 on success, < 0 on error.
"""
function ssh_bind_listen(ssh_bind_o)
    @ccall libssh.ssh_bind_listen(ssh_bind_o::ssh_bind)::Cint
end

"""
    ssh_bind_set_callbacks(sshbind, callbacks, userdata)

Set the callback for this bind.

```c++
     struct ssh_callbacks_struct cb = {
         .userdata = data,
         .auth_function = my_auth_function
     };
     ssh_callbacks_init(&cb);
     ssh_bind_set_callbacks(session, &cb);
```

# Arguments
* `sshbind`:\\[in\\] The bind to set the callback on.
* `callbacks`:\\[in\\] An already set up [`ssh_bind_callbacks`](@ref) instance.
* `userdata`:\\[in\\] A pointer to private data to pass to the callbacks.
# Returns
[`SSH_OK`](@ref) on success, [`SSH_ERROR`](@ref) if an error occurred.
"""
function ssh_bind_set_callbacks(sshbind, callbacks, userdata)
    @ccall libssh.ssh_bind_set_callbacks(sshbind::ssh_bind, callbacks::ssh_bind_callbacks, userdata::Ptr{Cvoid})::Cint
end

"""
    ssh_bind_set_blocking(ssh_bind_o, blocking)

Set the session to blocking/nonblocking mode.

# Arguments
* `ssh_bind_o`: The ssh server bind to use.
* `blocking`: Zero for nonblocking mode.
"""
function ssh_bind_set_blocking(ssh_bind_o, blocking)
    @ccall libssh.ssh_bind_set_blocking(ssh_bind_o::ssh_bind, blocking::Cint)::Cvoid
end

"""
    ssh_bind_get_fd(ssh_bind_o)

Recover the file descriptor from the session.

# Arguments
* `ssh_bind_o`: The ssh server bind to get the fd from.
# Returns
The file descriptor.
"""
function ssh_bind_get_fd(ssh_bind_o)
    @ccall libssh.ssh_bind_get_fd(ssh_bind_o::ssh_bind)::socket_t
end

"""
    ssh_bind_set_fd(ssh_bind_o, fd)

Set the file descriptor for a session.

# Arguments
* `ssh_bind_o`: The ssh server bind to set the fd.
* `fd`: The file descriptssh\\_bind B
"""
function ssh_bind_set_fd(ssh_bind_o, fd)
    @ccall libssh.ssh_bind_set_fd(ssh_bind_o::ssh_bind, fd::socket_t)::Cvoid
end

"""
    ssh_bind_fd_toaccept(ssh_bind_o)

Allow the file descriptor to accept new sessions.

# Arguments
* `ssh_bind_o`: The ssh server bind to use.
"""
function ssh_bind_fd_toaccept(ssh_bind_o)
    @ccall libssh.ssh_bind_fd_toaccept(ssh_bind_o::ssh_bind)::Cvoid
end

"""
    ssh_bind_accept(ssh_bind_o, session)

Accept an incoming ssh connection and initialize the session.

# Arguments
* `ssh_bind_o`: The ssh server bind to accept a connection.
* `session`:	A preallocated ssh session
# Returns
[`SSH_OK`](@ref) when a connection is established
# See also
[`ssh_new`](@ref)
"""
function ssh_bind_accept(ssh_bind_o, session)
    @ccall libssh.ssh_bind_accept(ssh_bind_o::ssh_bind, session::ssh_session)::Cint
end

"""
    ssh_bind_accept_fd(ssh_bind_o, session, fd)

Accept an incoming ssh connection on the given file descriptor and initialize the session.

# Arguments
* `ssh_bind_o`: The ssh server bind to accept a connection.
* `session`: A preallocated ssh session
* `fd`: A file descriptor of an already established TCP inbound connection
# Returns
[`SSH_OK`](@ref) when a connection is established
# See also
[`ssh_new`](@ref), [`ssh_bind_accept`](@ref)
"""
function ssh_bind_accept_fd(ssh_bind_o, session, fd)
    @ccall libssh.ssh_bind_accept_fd(ssh_bind_o::ssh_bind, session::ssh_session, fd::socket_t)::Cint
end

"""
    ssh_gssapi_get_creds(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__server.html#gab9ca89e12e290a701dced5f7c91bb677).
"""
function ssh_gssapi_get_creds(session)
    @ccall libssh.ssh_gssapi_get_creds(session::ssh_session)::ssh_gssapi_creds
end

"""
    ssh_handle_key_exchange(session)

Handles the key exchange and set up encryption

# Arguments
* `session`:	A connected ssh session
# Returns
[`SSH_OK`](@ref) if the key exchange was successful
# See also
[`ssh_bind_accept`](@ref)
"""
function ssh_handle_key_exchange(session)
    @ccall libssh.ssh_handle_key_exchange(session::ssh_session)::Cint
end

"""
    ssh_server_init_kex(session)

Initialize the set of key exchange, hostkey, ciphers, MACs, and compression algorithms for the given [`ssh_session`](@ref).

The selection of algorithms and keys used are determined by the options that are currently set in the given [`ssh_session`](@ref) structure. May only be called before the initial key exchange has begun.

# Arguments
* `session`: The session structure to initialize.
# Returns
[`SSH_OK`](@ref) if initialization succeeds.
# See also
[`ssh_handle_key_exchange`](@ref), [`ssh_options_set`](@ref)
"""
function ssh_server_init_kex(session)
    @ccall libssh.ssh_server_init_kex(session::ssh_session)::Cint
end

"""
    ssh_bind_free(ssh_bind_o)

Free a ssh servers bind.

Note that this will also free options that have been set on the bind, including keys set with SSH\\_BIND\\_OPTIONS\\_IMPORT\\_KEY.

# Arguments
* `ssh_bind_o`: The ssh server bind to free.
"""
function ssh_bind_free(ssh_bind_o)
    @ccall libssh.ssh_bind_free(ssh_bind_o::ssh_bind)::Cvoid
end

"""
    ssh_set_auth_methods(session, auth_methods)

Set the acceptable authentication methods to be sent to the client.

Supported methods are:

[`SSH_AUTH_METHOD_PASSWORD`](@ref) [`SSH_AUTH_METHOD_PUBLICKEY`](@ref) [`SSH_AUTH_METHOD_HOSTBASED`](@ref) [`SSH_AUTH_METHOD_INTERACTIVE`](@ref) [`SSH_AUTH_METHOD_GSSAPI_MIC`](@ref)

# Arguments
* `session`:\\[in\\] The server session
* `auth_methods`:\\[in\\] The authentication methods we will support, which can be bitwise-or'd.
"""
function ssh_set_auth_methods(session, auth_methods)
    @ccall libssh.ssh_set_auth_methods(session::ssh_session, auth_methods::Cint)::Cvoid
end

"""
    ssh_send_issue_banner(session, banner)

Send the server's issue-banner to client.

# Arguments
* `session`:\\[in\\] The server session.
* `banner`:\\[in\\] The server's banner.
# Returns
[`SSH_OK`](@ref) on success, [`SSH_ERROR`](@ref) on error.
"""
function ssh_send_issue_banner(session, banner)
    @ccall libssh.ssh_send_issue_banner(session::ssh_session, banner::ssh_string)::Cint
end

"""
    ssh_message_reply_default(msg; throw = true)

Auto-generated wrapper around `ssh_message_reply_default()`. Original upstream documentation is below.

---

Reply with a standard reject message.

Use this function if you don't know what to respond or if you want to reject a request.

# Arguments
* `msg`:\\[in\\] The message to use for the reply.
# Returns
0 on success, -1 on error.
# See also
[`ssh_message_get`](@ref)()
"""
function ssh_message_reply_default(msg; throw = true)
    ret = @ccall(libssh.ssh_message_reply_default(msg::ssh_message)::Cint)
    if ret != SSH_OK && throw
        Base.throw(LibSSHException("Error from ssh_message_reply_default, did not return SSH_OK: " * "$(ret)"))
    end
    return ret
end

"""
    ssh_message_auth_user(msg; throw = true)

Auto-generated wrapper around `ssh_message_auth_user()`. Original upstream documentation is below.

---

Get the name of the authenticated user.

# Arguments
* `msg`:\\[in\\] The message to get the username from.
# Returns
The username or NULL if an error occurred.
# See also
[`ssh_message_get`](@ref)(), [`ssh_message_type`](@ref)()
"""
function ssh_message_auth_user(msg; throw = true)
    ret = @ccall(libssh.ssh_message_auth_user(msg::ssh_message)::Ptr{Cchar})
    if ret == C_NULL
        if throw
            Base.throw(LibSSHException("Error from ssh_message_auth_user, no string found (returned C_NULL)"))
        else
            return ret
        end
    end
    return unsafe_string(Ptr{UInt8}(ret))
end

"""
    ssh_message_auth_password(msg; throw = true)

Auto-generated wrapper around `ssh_message_auth_password()`. Original upstream documentation is below.

---

Get the password of the authenticated user.

!!! compat "Deprecated"

    This function should not be used anymore as there is a callback based server implementation now auth\\_password\\_function.

# Arguments
* `msg`:\\[in\\] The message to get the password from.
# Returns
The password or NULL if an error occurred.
# See also
[`ssh_message_get`](@ref)(), [`ssh_message_type`](@ref)()
"""
function ssh_message_auth_password(msg; throw = true)
    ret = @ccall(libssh.ssh_message_auth_password(msg::ssh_message)::Ptr{Cchar})
    if ret == C_NULL
        if throw
            Base.throw(LibSSHException("Error from ssh_message_auth_password, no string found (returned C_NULL)"))
        else
            return ret
        end
    end
    return unsafe_string(Ptr{UInt8}(ret))
end

"""
    ssh_message_auth_pubkey(msg)

Get the publickey of the authenticated user.

If you need the key for later user you should duplicate it.

!!! compat "Deprecated"

    This function should not be used anymore as there is a callback based server implementation auth\\_pubkey\\_function.

# Arguments
* `msg`:\\[in\\] The message to get the public key from.
# Returns
The public key or NULL.
# See also
[`ssh_key_dup`](@ref)(), [`ssh_key_cmp`](@ref)(), [`ssh_message_get`](@ref)(), [`ssh_message_type`](@ref)()
"""
function ssh_message_auth_pubkey(msg)
    @ccall libssh.ssh_message_auth_pubkey(msg::ssh_message)::ssh_key
end

"""
    ssh_message_auth_kbdint_is_response(msg)

Auto-generated wrapper around [`ssh_message_auth_kbdint_is_response()`](https://api.libssh.org/stable/group__libssh__server.html#ga5132c82c49de985e9e10f51f393e52a4).
"""
function ssh_message_auth_kbdint_is_response(msg)
    ret = @ccall(libssh.ssh_message_auth_kbdint_is_response(msg::ssh_message)::Cint)
    return Bool(ret)
end

"""
    ssh_message_auth_publickey_state(msg)

!!! compat "Deprecated"

    This function should not be used anymore as there is a callback based server implementation auth\\_pubkey\\_function

# Arguments
* `msg`:\\[in\\] The message to get the public key state from.
"""
function ssh_message_auth_publickey_state(msg)
    @ccall libssh.ssh_message_auth_publickey_state(msg::ssh_message)::ssh_publickey_state_e
end

"""
    ssh_message_auth_reply_success(msg, partial; throw = true)

Auto-generated wrapper around `ssh_message_auth_reply_success()`.
"""
function ssh_message_auth_reply_success(msg, partial; throw = true)
    ret = @ccall(libssh.ssh_message_auth_reply_success(msg::ssh_message, partial::Cint)::Cint)
    if ret != SSH_OK && throw
        Base.throw(LibSSHException("Error from ssh_message_auth_reply_success, did not return SSH_OK: " * "$(ret)"))
    end
    return ret
end

"""
    ssh_message_auth_reply_pk_ok(msg, algo, pubkey)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__server.html#ga2ce88786e073b36991fc96c8f6b58c09).
"""
function ssh_message_auth_reply_pk_ok(msg, algo, pubkey)
    @ccall libssh.ssh_message_auth_reply_pk_ok(msg::ssh_message, algo::ssh_string, pubkey::ssh_string)::Cint
end

"""
    ssh_message_auth_reply_pk_ok_simple(msg)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__server.html#ga98321ead09cda145a08603d481a62a9e).
"""
function ssh_message_auth_reply_pk_ok_simple(msg)
    @ccall libssh.ssh_message_auth_reply_pk_ok_simple(msg::ssh_message)::Cint
end

"""
    ssh_message_auth_set_methods(msg, methods; throw = true)

Auto-generated wrapper around [`ssh_message_auth_set_methods()`](https://api.libssh.org/stable/group__libssh__server.html#gab993157d98e5b4b3399d216c9243effc).
"""
function ssh_message_auth_set_methods(msg, methods; throw = true)
    ret = @ccall(libssh.ssh_message_auth_set_methods(msg::ssh_message, methods::Cint)::Cint)
    if ret != SSH_OK && throw
        Base.throw(LibSSHException("Error from ssh_message_auth_set_methods, did not return SSH_OK: " * "$(ret)"))
    end
    return ret
end

"""
    ssh_message_auth_interactive_request(msg, name, instruction, num_prompts, prompts, echo)

Initiate keyboard-interactive authentication from a server.
"""
function ssh_message_auth_interactive_request(msg, name, instruction, num_prompts, prompts, echo)
    @ccall libssh.ssh_message_auth_interactive_request(msg::ssh_message, name::Ptr{Cchar}, instruction::Ptr{Cchar}, num_prompts::Cuint, prompts::Ptr{Ptr{Cchar}}, echo::Ptr{Cchar})::Cint
end

"""
    ssh_message_service_reply_success(msg)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__server.html#gad0bd348b84300149f017f5abbaff38f5).
"""
function ssh_message_service_reply_success(msg)
    @ccall libssh.ssh_message_service_reply_success(msg::ssh_message)::Cint
end

"""
    ssh_message_service_service(msg)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__server.html#ga9f9dedae252c1b786b1213c84ac90baa).
"""
function ssh_message_service_service(msg)
    @ccall libssh.ssh_message_service_service(msg::ssh_message)::Ptr{Cchar}
end

"""
    ssh_message_global_request_reply_success(msg, bound_port)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__server.html#ga9c09466e299aff371b2fba996054a6a2).
"""
function ssh_message_global_request_reply_success(msg, bound_port)
    @ccall libssh.ssh_message_global_request_reply_success(msg::ssh_message, bound_port::UInt16)::Cint
end

"""
    ssh_set_message_callback(session, ssh_bind_message_callback, data)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__server.html#gaccad877b20fca2d4a7eda5bebc1f5af1).
"""
function ssh_set_message_callback(session, ssh_bind_message_callback, data)
    @ccall libssh.ssh_set_message_callback(session::ssh_session, ssh_bind_message_callback::Ptr{Cvoid}, data::Ptr{Cvoid})::Cvoid
end

function ssh_execute_message_callbacks(session)
    @ccall libssh.ssh_execute_message_callbacks(session::ssh_session)::Cint
end

function ssh_message_channel_request_open_originator(msg)
    @ccall libssh.ssh_message_channel_request_open_originator(msg::ssh_message)::Ptr{Cchar}
end

function ssh_message_channel_request_open_originator_port(msg)
    @ccall libssh.ssh_message_channel_request_open_originator_port(msg::ssh_message)::Cint
end

function ssh_message_channel_request_open_destination(msg)
    @ccall libssh.ssh_message_channel_request_open_destination(msg::ssh_message)::Ptr{Cchar}
end

function ssh_message_channel_request_open_destination_port(msg)
    @ccall libssh.ssh_message_channel_request_open_destination_port(msg::ssh_message)::Cint
end

function ssh_message_channel_request_channel(msg)
    @ccall libssh.ssh_message_channel_request_channel(msg::ssh_message)::ssh_channel
end

function ssh_message_channel_request_pty_term(msg)
    @ccall libssh.ssh_message_channel_request_pty_term(msg::ssh_message)::Ptr{Cchar}
end

function ssh_message_channel_request_pty_width(msg)
    @ccall libssh.ssh_message_channel_request_pty_width(msg::ssh_message)::Cint
end

function ssh_message_channel_request_pty_height(msg)
    @ccall libssh.ssh_message_channel_request_pty_height(msg::ssh_message)::Cint
end

function ssh_message_channel_request_pty_pxwidth(msg)
    @ccall libssh.ssh_message_channel_request_pty_pxwidth(msg::ssh_message)::Cint
end

function ssh_message_channel_request_pty_pxheight(msg)
    @ccall libssh.ssh_message_channel_request_pty_pxheight(msg::ssh_message)::Cint
end

function ssh_message_channel_request_env_name(msg)
    @ccall libssh.ssh_message_channel_request_env_name(msg::ssh_message)::Ptr{Cchar}
end

function ssh_message_channel_request_env_value(msg)
    @ccall libssh.ssh_message_channel_request_env_value(msg::ssh_message)::Ptr{Cchar}
end

function ssh_message_channel_request_command(msg)
    @ccall libssh.ssh_message_channel_request_command(msg::ssh_message)::Ptr{Cchar}
end

function ssh_message_channel_request_subsystem(msg)
    @ccall libssh.ssh_message_channel_request_subsystem(msg::ssh_message)::Ptr{Cchar}
end

function ssh_message_channel_request_x11_single_connection(msg)
    @ccall libssh.ssh_message_channel_request_x11_single_connection(msg::ssh_message)::Cint
end

function ssh_message_channel_request_x11_auth_protocol(msg)
    @ccall libssh.ssh_message_channel_request_x11_auth_protocol(msg::ssh_message)::Ptr{Cchar}
end

function ssh_message_channel_request_x11_auth_cookie(msg)
    @ccall libssh.ssh_message_channel_request_x11_auth_cookie(msg::ssh_message)::Ptr{Cchar}
end

function ssh_message_channel_request_x11_screen_number(msg)
    @ccall libssh.ssh_message_channel_request_x11_screen_number(msg::ssh_message)::Cint
end

function ssh_message_global_request_address(msg)
    @ccall libssh.ssh_message_global_request_address(msg::ssh_message)::Ptr{Cchar}
end

function ssh_message_global_request_port(msg)
    @ccall libssh.ssh_message_global_request_port(msg::ssh_message)::Cint
end

"""
    ssh_channel_open_reverse_forward(channel, remotehost, remoteport, sourcehost, localport)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#ga9f66bf86a741ba17fe097dcb0594260e).
"""
function ssh_channel_open_reverse_forward(channel, remotehost, remoteport, sourcehost, localport)
    @ccall libssh.ssh_channel_open_reverse_forward(channel::ssh_channel, remotehost::Ptr{Cchar}, remoteport::Cint, sourcehost::Ptr{Cchar}, localport::Cint)::Cint
end

"""
    ssh_channel_request_send_exit_status(channel, exit_status)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gadc35e456e45b92c1e1da0fff8b6dfec9).
"""
function ssh_channel_request_send_exit_status(channel, exit_status)
    @ccall libssh.ssh_channel_request_send_exit_status(channel::ssh_channel, exit_status::Cint)::Cint
end

"""
    ssh_channel_request_send_exit_signal(channel, signum, core, errmsg, lang)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__channel.html#gabd3a5c8ef800f6c6ffdcc5f62557434c).
"""
function ssh_channel_request_send_exit_signal(channel, signum, core, errmsg, lang)
    @ccall libssh.ssh_channel_request_send_exit_signal(channel::ssh_channel, signum::Ptr{Cchar}, core::Cint, errmsg::Ptr{Cchar}, lang::Ptr{Cchar})::Cint
end

"""
    ssh_send_keepalive(session)

[Upstream documentation](https://api.libssh.org/stable/group__libssh__server.html#gaa1ac2e1b7fdc23fd7e253aa9f0a47e7a).
"""
function ssh_send_keepalive(session)
    @ccall libssh.ssh_send_keepalive(session::ssh_session)::Cint
end

function ssh_accept(session)
    @ccall libssh.ssh_accept(session::ssh_session)::Cint
end

function channel_write_stderr(channel, data, len)
    @ccall libssh.channel_write_stderr(channel::ssh_channel, data::Ptr{Cvoid}, len::UInt32)::Cint
end

# typedef void ( * ssh_callback_int ) ( int code , void * user )
"""
```c++
 @brief callback to process simple codes
 @param code value to transmit
 @param user Userdata to pass in callback
 

```
"""
const ssh_callback_int = Ptr{Cvoid}

# typedef size_t ( * ssh_callback_data ) ( const void * data , size_t len , void * user )
"""
```c++
 @brief callback for data received messages.
 @param data data retrieved from the socket or stream
 @param len number of bytes available from this stream
 @param user user-supplied pointer sent along with all callback messages
 @returns number of bytes processed by the callee. The remaining bytes will
 be sent in the next callback message, when more data is available.
 

```
"""
const ssh_callback_data = Ptr{Cvoid}

# typedef void ( * ssh_callback_int_int ) ( int code , int errno_code , void * user )
const ssh_callback_int_int = Ptr{Cvoid}

# typedef int ( * ssh_message_callback ) ( ssh_session , ssh_message message , void * user )
const ssh_message_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_callback_int ) ( ssh_channel channel , int code , void * user )
const ssh_channel_callback_int = Ptr{Cvoid}

# typedef int ( * ssh_channel_callback_data ) ( ssh_channel channel , int code , void * data , size_t len , void * user )
const ssh_channel_callback_data = Ptr{Cvoid}

# typedef void ( * ssh_log_callback ) ( ssh_session session , int priority , const char * message , void * userdata )
"""
SSH log callback. All logging messages will go through this callback

# Arguments
* `session`: Current session handler
* `priority`: Priority of the log, the smaller being the more important
* `message`: the actual message
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_log_callback = Ptr{Cvoid}

# typedef void ( * ssh_logging_callback ) ( int priority , const char * function , const char * buffer , void * userdata )
"""
SSH log callback.

All logging messages will go through this callback.

# Arguments
* `priority`: Priority of the log, the smaller being the more important.
* `function`: The function name calling the logging functions.
* `buffer`: The actual message
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_logging_callback = Ptr{Cvoid}

# typedef void ( * ssh_status_callback ) ( ssh_session session , float status , void * userdata )
"""
SSH Connection status callback.

# Arguments
* `session`: Current session handler
* `status`: Percentage of connection status, going from 0.0 to 1.0 once connection is done.
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_status_callback = Ptr{Cvoid}

# typedef void ( * ssh_global_request_callback ) ( ssh_session session , ssh_message message , void * userdata )
"""
SSH global request callback. All global request will go through this callback.

# Arguments
* `session`: Current session handler
* `message`: the actual message
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_global_request_callback = Ptr{Cvoid}

# typedef ssh_channel ( * ssh_channel_open_request_x11_callback ) ( ssh_session session , const char * originator_address , int originator_port , void * userdata )
"""
Handles an SSH new channel open X11 request. This happens when the server sends back an X11 connection attempt. This is a client-side API

!!! warning

    The channel pointer returned by this callback must be closed by the application.

# Arguments
* `session`: current session handler
* `userdata`: Userdata to be passed to the callback function.
* `originator_address`: IP address of the machine who sent the request
* `originator_port`: port number of the machine who sent the request
# Returns
NULL if the request should not be allowed
"""
const ssh_channel_open_request_x11_callback = Ptr{Cvoid}

# typedef ssh_channel ( * ssh_channel_open_request_auth_agent_callback ) ( ssh_session session , void * userdata )
"""
Handles an SSH new channel open "auth-agent" request. This happens when the server sends back an "auth-agent" connection attempt. This is a client-side API

!!! warning

    The channel pointer returned by this callback must be closed by the application.

# Arguments
* `session`: current session handler
* `userdata`: Userdata to be passed to the callback function.
# Returns
NULL if the request should not be allowed
"""
const ssh_channel_open_request_auth_agent_callback = Ptr{Cvoid}

# typedef ssh_channel ( * ssh_channel_open_request_forwarded_tcpip_callback ) ( ssh_session session , const char * destination_address , int destination_port , const char * originator_address , int originator_port , void * userdata )
"""
Handles an SSH new channel open "forwarded-tcpip" request. This happens when the server forwards an incoming TCP connection on a port it was previously requested to listen on. This is a client-side API

!!! warning

    The channel pointer returned by this callback must be closed by the application.

# Arguments
* `session`: current session handler
* `destination_address`: the address that the TCP connection connected to
* `destination_port`: the port that the TCP connection connected to
* `originator_address`: the originator IP address
* `originator_port`: the originator port
* `userdata`: Userdata to be passed to the callback function.
# Returns
NULL if the request should not be allowed
"""
const ssh_channel_open_request_forwarded_tcpip_callback = Ptr{Cvoid}

"""
    ssh_callbacks_struct

The structure to replace libssh functions with appropriate callbacks.
"""
mutable struct ssh_callbacks_struct
    size::Csize_t
    userdata::Ptr{Cvoid}
    auth_function::ssh_auth_callback
    log_function::ssh_log_callback
    connect_status_function::Ptr{Cvoid}
    global_request_function::ssh_global_request_callback
    channel_open_request_x11_function::ssh_channel_open_request_x11_callback
    channel_open_request_auth_agent_function::ssh_channel_open_request_auth_agent_callback
    channel_open_request_forwarded_tcpip_function::ssh_channel_open_request_forwarded_tcpip_callback
end

const ssh_callbacks = Ptr{ssh_callbacks_struct}

# typedef int ( * ssh_auth_password_callback ) ( ssh_session session , const char * user , const char * password , void * userdata )
"""
SSH authentication callback.

# Arguments
* `session`: Current session handler
* `user`: User that wants to authenticate
* `password`: Password used for authentication
* `userdata`: Userdata to be passed to the callback function.
# Returns
SSH\\_AUTH\\_DENIED Authentication failed.
"""
const ssh_auth_password_callback = Ptr{Cvoid}

# typedef int ( * ssh_auth_none_callback ) ( ssh_session session , const char * user , void * userdata )
"""
SSH authentication callback. Tries to authenticates user with the "none" method which is anonymous or passwordless.

# Arguments
* `session`: Current session handler
* `user`: User that wants to authenticate
* `userdata`: Userdata to be passed to the callback function.
# Returns
SSH\\_AUTH\\_DENIED Authentication failed.
"""
const ssh_auth_none_callback = Ptr{Cvoid}

# typedef int ( * ssh_auth_gssapi_mic_callback ) ( ssh_session session , const char * user , const char * principal , void * userdata )
"""
SSH authentication callback. Tries to authenticates user with the "gssapi-with-mic" method

!!! warning

    Implementations should verify that parameter user matches in some way the principal. user and principal can be different. Only the latter is guaranteed to be safe.

# Arguments
* `session`: Current session handler
* `user`: Username of the user (can be spoofed)
* `principal`: Authenticated principal of the user, including realm.
* `userdata`: Userdata to be passed to the callback function.
# Returns
SSH\\_AUTH\\_DENIED Authentication failed.
"""
const ssh_auth_gssapi_mic_callback = Ptr{Cvoid}

# typedef int ( * ssh_auth_pubkey_callback ) ( ssh_session session , const char * user , struct ssh_key_struct * pubkey , char signature_state , void * userdata )
"""
SSH authentication callback.

# Arguments
* `session`: Current session handler
* `user`: User that wants to authenticate
* `pubkey`: public key used for authentication
* `signature_state`: SSH\\_PUBLICKEY\\_STATE\\_NONE if the key is not signed (simple public key probe),	SSH\\_PUBLICKEY\\_STATE\\_VALID if the signature is valid. Others values should be	replied with a SSH\\_AUTH\\_DENIED.
* `userdata`: Userdata to be passed to the callback function.
# Returns
SSH\\_AUTH\\_DENIED Authentication failed.
"""
const ssh_auth_pubkey_callback = Ptr{Cvoid}

# typedef int ( * ssh_service_request_callback ) ( ssh_session session , const char * service , void * userdata )
"""
Handles an SSH service request

# Arguments
* `session`: current session handler
* `service`: name of the service (e.g. "ssh-userauth") requested
* `userdata`: Userdata to be passed to the callback function.
# Returns
-1 if the request should not be allowed
"""
const ssh_service_request_callback = Ptr{Cvoid}

# typedef ssh_channel ( * ssh_channel_open_request_session_callback ) ( ssh_session session , void * userdata )
"""
Handles an SSH new channel open session request

!!! warning

    The channel pointer returned by this callback must be closed by the application.

# Arguments
* `session`: current session handler
* `userdata`: Userdata to be passed to the callback function.
# Returns
NULL if the request should not be allowed
"""
const ssh_channel_open_request_session_callback = Ptr{Cvoid}

# typedef ssh_string ( * ssh_gssapi_select_oid_callback ) ( ssh_session session , const char * user , int n_oid , ssh_string * oids , void * userdata )
const ssh_gssapi_select_oid_callback = Ptr{Cvoid}

# typedef int ( * ssh_gssapi_accept_sec_ctx_callback ) ( ssh_session session , ssh_string input_token , ssh_string * output_token , void * userdata )
const ssh_gssapi_accept_sec_ctx_callback = Ptr{Cvoid}

# typedef int ( * ssh_gssapi_verify_mic_callback ) ( ssh_session session , ssh_string mic , void * mic_buffer , size_t mic_buffer_size , void * userdata )
const ssh_gssapi_verify_mic_callback = Ptr{Cvoid}

"""
    ssh_server_callbacks_struct

This structure can be used to implement a libssh server, with appropriate callbacks.
"""
mutable struct ssh_server_callbacks_struct
    size::Csize_t
    userdata::Ptr{Cvoid}
    auth_password_function::ssh_auth_password_callback
    auth_none_function::ssh_auth_none_callback
    auth_gssapi_mic_function::ssh_auth_gssapi_mic_callback
    auth_pubkey_function::ssh_auth_pubkey_callback
    service_request_function::ssh_service_request_callback
    channel_open_request_session_function::ssh_channel_open_request_session_callback
    gssapi_select_oid_function::ssh_gssapi_select_oid_callback
    gssapi_accept_sec_ctx_function::ssh_gssapi_accept_sec_ctx_callback
    gssapi_verify_mic_function::ssh_gssapi_verify_mic_callback
end
function Base.getproperty(x::Ptr{ssh_server_callbacks_struct}, f::Symbol)
    f === :size && return Ptr{Csize_t}(x + 0)
    f === :userdata && return Ptr{Ptr{Cvoid}}(x + 8)
    f === :auth_password_function && return Ptr{ssh_auth_password_callback}(x + 16)
    f === :auth_none_function && return Ptr{ssh_auth_none_callback}(x + 24)
    f === :auth_gssapi_mic_function && return Ptr{ssh_auth_gssapi_mic_callback}(x + 32)
    f === :auth_pubkey_function && return Ptr{ssh_auth_pubkey_callback}(x + 40)
    f === :service_request_function && return Ptr{ssh_service_request_callback}(x + 48)
    f === :channel_open_request_session_function && return Ptr{ssh_channel_open_request_session_callback}(x + 56)
    f === :gssapi_select_oid_function && return Ptr{ssh_gssapi_select_oid_callback}(x + 64)
    f === :gssapi_accept_sec_ctx_function && return Ptr{ssh_gssapi_accept_sec_ctx_callback}(x + 72)
    f === :gssapi_verify_mic_function && return Ptr{ssh_gssapi_verify_mic_callback}(x + 80)
    return getfield(x, f)
end

function Base.setproperty!(x::Ptr{ssh_server_callbacks_struct}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const ssh_server_callbacks = Ptr{ssh_server_callbacks_struct}

"""
    ssh_set_server_callbacks(session, cb)

Set the session server callback functions.

This functions sets the callback structure to use your own callback functions for user authentication, new channels and requests.

Note, that the structure is not copied to the session structure so it needs to be valid for the whole session lifetime.

```c++
 struct ssh_server_callbacks_struct cb = {
   .userdata = data,
   .auth_password_function = my_auth_function
 };
 ssh_callbacks_init(&cb);
 ssh_set_server_callbacks(session, &cb);
```

# Arguments
* `session`: The session to set the callback structure.
* `cb`: The callback structure itself.
# Returns
[`SSH_OK`](@ref) on success, [`SSH_ERROR`](@ref) on error.
"""
function ssh_set_server_callbacks(session, cb)
    @ccall libssh.ssh_set_server_callbacks(session::ssh_session, cb::ssh_server_callbacks)::Cint
end

"""
    ssh_socket_callbacks_struct

These are the callbacks exported by the socket structure They are called by the socket module when a socket event appears
"""
mutable struct ssh_socket_callbacks_struct
    userdata::Ptr{Cvoid}
    data::ssh_callback_data
    controlflow::ssh_callback_int
    exception::ssh_callback_int_int
    connected::ssh_callback_int_int
end

const ssh_socket_callbacks = Ptr{ssh_socket_callbacks_struct}

# typedef int ( * ssh_packet_callback ) ( ssh_session session , uint8_t type , ssh_buffer packet , void * user )
"""
Prototype for a packet callback, to be called when a new packet arrives

# Arguments
* `session`: The current session of the packet
* `type`: packet type (see ssh2.h)
* `packet`: buffer containing the packet, excluding size, type and padding fields
* `user`: user argument to the callback and are called each time a packet shows up
# Returns
[`SSH_PACKET_NOT_USED`](@ref) Packet was not used or understood, processing must continue
"""
const ssh_packet_callback = Ptr{Cvoid}

mutable struct ssh_packet_callbacks_struct
    start::UInt8
    n_callbacks::UInt8
    callbacks::Ptr{ssh_packet_callback}
    user::Ptr{Cvoid}
end

const ssh_packet_callbacks = Ptr{ssh_packet_callbacks_struct}

"""
    ssh_set_callbacks(session, cb)

Set the session callback functions.

This functions sets the callback structure to use your own callback functions for auth, logging and status.

Note, that the callback structure is not copied into the session so it needs to be valid for the whole session lifetime.

```c++
 struct ssh_callbacks_struct cb = {
   .userdata = data,
   .auth_function = my_auth_function
 };
 ssh_callbacks_init(&cb);
 ssh_set_callbacks(session, &cb);
```

# Arguments
* `session`: The session to set the callback structure.
* `cb`: The callback structure itself.
# Returns
[`SSH_OK`](@ref) on success, [`SSH_ERROR`](@ref) on error.
"""
function ssh_set_callbacks(session, cb)
    @ccall libssh.ssh_set_callbacks(session::ssh_session, cb::ssh_callbacks)::Cint
end

# typedef int ( * ssh_channel_data_callback ) ( ssh_session session , ssh_channel channel , void * data , uint32_t len , int is_stderr , void * userdata )
"""
SSH channel data callback. Called when data is available on a channel

# Arguments
* `session`: Current session handler
* `channel`: the actual channel
* `data`: the data that has been read on the channel
* `len`: the length of the data
* `is_stderr`: is 0 for stdout or 1 for stderr
* `userdata`: Userdata to be passed to the callback function.
# Returns
number of bytes processed by the callee. The remaining bytes will be sent in the next callback message, when more data is available.
"""
const ssh_channel_data_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_eof_callback ) ( ssh_session session , ssh_channel channel , void * userdata )
"""
SSH channel eof callback. Called when a channel receives EOF

# Arguments
* `session`: Current session handler
* `channel`: the actual channel
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_channel_eof_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_close_callback ) ( ssh_session session , ssh_channel channel , void * userdata )
"""
SSH channel close callback. Called when a channel is closed by remote peer

# Arguments
* `session`: Current session handler
* `channel`: the actual channel
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_channel_close_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_signal_callback ) ( ssh_session session , ssh_channel channel , const char * signal , void * userdata )
"""
SSH channel signal callback. Called when a channel has received a signal

# Arguments
* `session`: Current session handler
* `channel`: the actual channel
* `signal`: the signal name (without the SIG prefix)
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_channel_signal_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_exit_status_callback ) ( ssh_session session , ssh_channel channel , int exit_status , void * userdata )
"""
SSH channel exit status callback. Called when a channel has received an exit status

# Arguments
* `session`: Current session handler
* `channel`: the actual channel
* `exit_status`: Exit status of the ran command
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_channel_exit_status_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_exit_signal_callback ) ( ssh_session session , ssh_channel channel , const char * signal , int core , const char * errmsg , const char * lang , void * userdata )
"""
SSH channel exit signal callback. Called when a channel has received an exit signal

# Arguments
* `session`: Current session handler
* `channel`: the actual channel
* `signal`: the signal name (without the SIG prefix)
* `core`: a boolean telling whether a core has been dumped or not
* `errmsg`: the description of the exception
* `lang`: the language of the description (format: RFC 3066)
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_channel_exit_signal_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_pty_request_callback ) ( ssh_session session , ssh_channel channel , const char * term , int width , int height , int pxwidth , int pwheight , void * userdata )
"""
SSH channel PTY request from a client.

# Arguments
* `session`: the session
* `channel`: the channel
* `term`: The type of terminal emulation
* `width`: width of the terminal, in characters
* `height`: height of the terminal, in characters
* `pxwidth`: width of the terminal, in pixels
* `pwheight`: height of the terminal, in pixels
* `userdata`: Userdata to be passed to the callback function.
# Returns
-1 if the request is denied
"""
const ssh_channel_pty_request_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_shell_request_callback ) ( ssh_session session , ssh_channel channel , void * userdata )
"""
SSH channel Shell request from a client.

# Arguments
* `session`: the session
* `channel`: the channel
* `userdata`: Userdata to be passed to the callback function.
# Returns
1 if the request is denied
"""
const ssh_channel_shell_request_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_auth_agent_req_callback ) ( ssh_session session , ssh_channel channel , void * userdata )
"""
SSH auth-agent-request from the client. This request is sent by a client when agent forwarding is available. Server is free to ignore this callback, no answer is expected.

# Arguments
* `session`: the session
* `channel`: the channel
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_channel_auth_agent_req_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_x11_req_callback ) ( ssh_session session , ssh_channel channel , int single_connection , const char * auth_protocol , const char * auth_cookie , uint32_t screen_number , void * userdata )
"""
SSH X11 request from the client. This request is sent by a client when X11 forwarding is requested(and available). Server is free to ignore this callback, no answer is expected.

# Arguments
* `session`: the session
* `channel`: the channel
* `single_connection`: If true, only one channel should be forwarded
* `auth_protocol`: The X11 authentication method to be used
* `auth_cookie`: Authentication cookie encoded hexadecimal
* `screen_number`: Screen number
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_channel_x11_req_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_pty_window_change_callback ) ( ssh_session session , ssh_channel channel , int width , int height , int pxwidth , int pwheight , void * userdata )
"""
SSH channel PTY windows change (terminal size) from a client.

# Arguments
* `session`: the session
* `channel`: the channel
* `width`: width of the terminal, in characters
* `height`: height of the terminal, in characters
* `pxwidth`: width of the terminal, in pixels
* `pwheight`: height of the terminal, in pixels
* `userdata`: Userdata to be passed to the callback function.
# Returns
-1 if the request is denied
"""
const ssh_channel_pty_window_change_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_exec_request_callback ) ( ssh_session session , ssh_channel channel , const char * command , void * userdata )
"""
SSH channel Exec request from a client.

# Arguments
* `session`: the session
* `channel`: the channel
* `command`: the shell command to be executed
* `userdata`: Userdata to be passed to the callback function.
# Returns
1 if the request is denied
"""
const ssh_channel_exec_request_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_env_request_callback ) ( ssh_session session , ssh_channel channel , const char * env_name , const char * env_value , void * userdata )
"""
SSH channel environment request from a client.

!!! warning

    some environment variables can be dangerous if changed (e.g. LD\\_PRELOAD) and should not be fulfilled.

# Arguments
* `session`: the session
* `channel`: the channel
* `env_name`: name of the environment value to be set
* `env_value`: value of the environment value to be set
* `userdata`: Userdata to be passed to the callback function.
# Returns
1 if the request is denied
"""
const ssh_channel_env_request_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_subsystem_request_callback ) ( ssh_session session , ssh_channel channel , const char * subsystem , void * userdata )
"""
SSH channel subsystem request from a client.

# Arguments
* `session`: the session
* `channel`: the channel
* `subsystem`: the subsystem required
* `userdata`: Userdata to be passed to the callback function.
# Returns
1 if the request is denied
"""
const ssh_channel_subsystem_request_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_write_wontblock_callback ) ( ssh_session session , ssh_channel channel , uint32_t bytes , void * userdata )
"""
SSH channel write will not block (flow control).

# Arguments
* `session`: the session
* `channel`: the channel
* `bytes`:\\[in\\] size of the remote window in bytes. Writing as much data will not block.
* `userdata`:\\[in\\] Userdata to be passed to the callback function.
# Returns
0 default return value (other return codes may be added in future).
"""
const ssh_channel_write_wontblock_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_open_resp_callback ) ( ssh_session session , ssh_channel channel , bool is_success , void * userdata )
"""
SSH channel open callback. Called when a channel open succeeds or fails.

# Arguments
* `session`: Current session handler
* `channel`: the actual channel
* `is_success`: is 1 when the open succeeds, and 0 otherwise.
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_channel_open_resp_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_request_resp_callback ) ( ssh_session session , ssh_channel channel , void * userdata )
"""
SSH channel request response callback. Called when a response to the pending request is received.

# Arguments
* `session`: Current session handler
* `channel`: the actual channel
* `userdata`: Userdata to be passed to the callback function.
"""
const ssh_channel_request_resp_callback = Ptr{Cvoid}

mutable struct ssh_channel_callbacks_struct
    size::Csize_t
    userdata::Ptr{Cvoid}
    channel_data_function::ssh_channel_data_callback
    channel_eof_function::ssh_channel_eof_callback
    channel_close_function::ssh_channel_close_callback
    channel_signal_function::ssh_channel_signal_callback
    channel_exit_status_function::ssh_channel_exit_status_callback
    channel_exit_signal_function::ssh_channel_exit_signal_callback
    channel_pty_request_function::ssh_channel_pty_request_callback
    channel_shell_request_function::ssh_channel_shell_request_callback
    channel_auth_agent_req_function::ssh_channel_auth_agent_req_callback
    channel_x11_req_function::ssh_channel_x11_req_callback
    channel_pty_window_change_function::ssh_channel_pty_window_change_callback
    channel_exec_request_function::ssh_channel_exec_request_callback
    channel_env_request_function::ssh_channel_env_request_callback
    channel_subsystem_request_function::ssh_channel_subsystem_request_callback
    channel_write_wontblock_function::ssh_channel_write_wontblock_callback
    channel_open_response_function::ssh_channel_open_resp_callback
    channel_request_response_function::ssh_channel_request_resp_callback
end
function Base.getproperty(x::Ptr{ssh_channel_callbacks_struct}, f::Symbol)
    f === :size && return Ptr{Csize_t}(x + 0)
    f === :userdata && return Ptr{Ptr{Cvoid}}(x + 8)
    f === :channel_data_function && return Ptr{ssh_channel_data_callback}(x + 16)
    f === :channel_eof_function && return Ptr{ssh_channel_eof_callback}(x + 24)
    f === :channel_close_function && return Ptr{ssh_channel_close_callback}(x + 32)
    f === :channel_signal_function && return Ptr{ssh_channel_signal_callback}(x + 40)
    f === :channel_exit_status_function && return Ptr{ssh_channel_exit_status_callback}(x + 48)
    f === :channel_exit_signal_function && return Ptr{ssh_channel_exit_signal_callback}(x + 56)
    f === :channel_pty_request_function && return Ptr{ssh_channel_pty_request_callback}(x + 64)
    f === :channel_shell_request_function && return Ptr{ssh_channel_shell_request_callback}(x + 72)
    f === :channel_auth_agent_req_function && return Ptr{ssh_channel_auth_agent_req_callback}(x + 80)
    f === :channel_x11_req_function && return Ptr{ssh_channel_x11_req_callback}(x + 88)
    f === :channel_pty_window_change_function && return Ptr{ssh_channel_pty_window_change_callback}(x + 96)
    f === :channel_exec_request_function && return Ptr{ssh_channel_exec_request_callback}(x + 104)
    f === :channel_env_request_function && return Ptr{ssh_channel_env_request_callback}(x + 112)
    f === :channel_subsystem_request_function && return Ptr{ssh_channel_subsystem_request_callback}(x + 120)
    f === :channel_write_wontblock_function && return Ptr{ssh_channel_write_wontblock_callback}(x + 128)
    f === :channel_open_response_function && return Ptr{ssh_channel_open_resp_callback}(x + 136)
    f === :channel_request_response_function && return Ptr{ssh_channel_request_resp_callback}(x + 144)
    return getfield(x, f)
end

function Base.setproperty!(x::Ptr{ssh_channel_callbacks_struct}, f::Symbol, v)
    unsafe_store!(getproperty(x, f), v)
end


const ssh_channel_callbacks = Ptr{ssh_channel_callbacks_struct}

"""
    ssh_set_channel_callbacks(channel, cb)

Set the channel callback functions.

This functions sets the callback structure to use your own callback functions for channel data and exceptions.

Note, that the structure is not copied to the channel structure so it needs to be valid as for the whole life of the channel or until it is removed with [`ssh_remove_channel_callbacks`](@ref)().

```c++
 struct ssh_channel_callbacks_struct cb = {
   .userdata = data,
   .channel_data_function = my_channel_data_function
 };
 ssh_callbacks_init(&cb);
 ssh_set_channel_callbacks(channel, &cb);
```

!!! warning

    this function will not replace existing callbacks but set the new one atop of them.

# Arguments
* `channel`: The channel to set the callback structure.
* `cb`: The callback structure itself.
# Returns
[`SSH_OK`](@ref) on success, [`SSH_ERROR`](@ref) on error.
"""
function ssh_set_channel_callbacks(channel, cb)
    @ccall libssh.ssh_set_channel_callbacks(channel::ssh_channel, cb::ssh_channel_callbacks)::Cint
end

"""
    ssh_add_channel_callbacks(channel, cb)

Add channel callback functions

This function will add channel callback functions to the channel callback list. Callbacks missing from a callback structure will be probed in the next on the list.

# Arguments
* `channel`: The channel to set the callback structure.
* `cb`: The callback structure itself.
# Returns
[`SSH_OK`](@ref) on success, [`SSH_ERROR`](@ref) on error.
# See also
[`ssh_set_channel_callbacks`](@ref)
"""
function ssh_add_channel_callbacks(channel, cb)
    @ccall libssh.ssh_add_channel_callbacks(channel::ssh_channel, cb::ssh_channel_callbacks)::Cint
end

"""
    ssh_remove_channel_callbacks(channel, cb)

Remove a channel callback.

The channel has been added with [`ssh_add_channel_callbacks`](@ref) or [`ssh_set_channel_callbacks`](@ref) in this case.

# Arguments
* `channel`: The channel to remove the callback structure from.
* `cb`: The callback structure to remove
# Returns
[`SSH_OK`](@ref) on success, [`SSH_ERROR`](@ref) on error.
"""
function ssh_remove_channel_callbacks(channel, cb)
    @ccall libssh.ssh_remove_channel_callbacks(channel::ssh_channel, cb::ssh_channel_callbacks)::Cint
end

# typedef int ( * ssh_thread_callback ) ( void * * lock )
"""
` libssh_threads`

@{
"""
const ssh_thread_callback = Ptr{Cvoid}

# typedef unsigned long ( * ssh_thread_id_callback ) ( void )
const ssh_thread_id_callback = Ptr{Cvoid}

"""
    ssh_threads_callbacks_struct

Threads callbacks. See [`ssh_threads_set_callbacks`](@ref)
"""
mutable struct ssh_threads_callbacks_struct
    type::Ptr{Cchar}
    mutex_init::ssh_thread_callback
    mutex_destroy::ssh_thread_callback
    mutex_lock::ssh_thread_callback
    mutex_unlock::ssh_thread_callback
    thread_id::ssh_thread_id_callback
end

"""
    ssh_threads_set_callbacks(cb)

Set the thread callbacks structure.

This is necessary if your program is using libssh in a multithreaded fashion. This function must be called first, outside of any threading context (in your main() function for instance), before you call [`ssh_init`](@ref)().

!!! danger "Known bug"

    libgcrypt 1.6 and bigger backend does not support custom callback. Using anything else than pthreads here will fail.

# Arguments
* `cb`:\\[in\\] A pointer to a [`ssh_threads_callbacks_struct`](@ref) structure, which contains the different callbacks to be set.
# Returns
Always returns [`SSH_OK`](@ref).
# See also
[`ssh_threads_callbacks_struct`](@ref), SSH\\_THREADS\\_PTHREAD
"""
function ssh_threads_set_callbacks(cb)
    @ccall libssh.ssh_threads_set_callbacks(cb::Ptr{ssh_threads_callbacks_struct})::Cint
end

"""
    ssh_threads_get_default()

Returns a pointer to the appropriate callbacks structure for the environment, to be used with [`ssh_threads_set_callbacks`](@ref).

# Returns
A pointer to a [`ssh_threads_callbacks_struct`](@ref) to be used with [`ssh_threads_set_callbacks`](@ref).
# See also
[`ssh_threads_set_callbacks`](@ref)
"""
function ssh_threads_get_default()
    @ccall libssh.ssh_threads_get_default()::Ptr{ssh_threads_callbacks_struct}
end

"""
    ssh_threads_get_pthread()

Returns a pointer on the pthread threads callbacks, to be used with [`ssh_threads_set_callbacks`](@ref).

# See also
[`ssh_threads_set_callbacks`](@ref)
"""
function ssh_threads_get_pthread()
    @ccall libssh.ssh_threads_get_pthread()::Ptr{ssh_threads_callbacks_struct}
end

"""
    ssh_threads_get_noop()

Get the noop threads callbacks structure

This can be used with [`ssh_threads_set_callbacks`](@ref). These callbacks do nothing and are being used by default.

# Returns
Always returns a valid pointer to the noop callbacks structure.
# See also
[`ssh_threads_set_callbacks`](@ref)
"""
function ssh_threads_get_noop()
    @ccall libssh.ssh_threads_get_noop()::Ptr{ssh_threads_callbacks_struct}
end

"""
    ssh_set_log_callback(cb)

Set the logging callback function.

# Arguments
* `cb`:\\[in\\] The callback to set.
# Returns
0 on success, < 0 on error.
"""
function ssh_set_log_callback(cb)
    @ccall libssh.ssh_set_log_callback(cb::ssh_logging_callback)::Cint
end

"""
    ssh_get_log_callback()

Get the pointer to the logging callback function.

# Returns
The pointer the the callback or NULL if none set.
"""
function ssh_get_log_callback()
    @ccall libssh.ssh_get_log_callback()::ssh_logging_callback
end

# typedef int ( * ssh_jump_before_connection_callback ) ( ssh_session session , void * userdata )
"""
SSH proxyjump before connection callback. Called before calling [`ssh_connect`](@ref)()

# Arguments
* `session`: Jump session handler
* `userdata`: Userdata to be passed to the callback function.
# Returns
0 on success, < 0 on error.
"""
const ssh_jump_before_connection_callback = Ptr{Cvoid}

# typedef int ( * ssh_jump_verify_knownhost_callback ) ( ssh_session session , void * userdata )
"""
SSH proxyjump verify knownhost callback. Verify the host. If not specified default function will be used.

# Arguments
* `session`: Jump session handler
* `userdata`: Userdata to be passed to the callback function.
# Returns
0 on success, < 0 on error.
"""
const ssh_jump_verify_knownhost_callback = Ptr{Cvoid}

# typedef int ( * ssh_jump_authenticate_callback ) ( ssh_session session , void * userdata )
"""
SSH proxyjump user authentication callback. Authenticate the user.

# Arguments
* `session`: Jump session handler
* `userdata`: Userdata to be passed to the callback function.
# Returns
0 on success, < 0 on error.
"""
const ssh_jump_authenticate_callback = Ptr{Cvoid}

mutable struct ssh_jump_callbacks_struct
    userdata::Ptr{Cvoid}
    before_connection::ssh_jump_before_connection_callback
    verify_knownhost::ssh_jump_verify_knownhost_callback
    authenticate::ssh_jump_authenticate_callback
end

# Skipping MacroDefinition: LIBSSH_API __attribute__ ( ( visibility ( "default" ) ) )

# Skipping MacroDefinition: SSH_DEPRECATED __attribute__ ( ( deprecated ) )

const SSH_INVALID_SOCKET = socket_t(-1)

const SSH_CRYPT = 2

const SSH_MAC = 3

const SSH_COMP = 4

const SSH_LANG = 5

"""
Auth method enum ([upstream documentation](https://api.libssh.org/stable/libssh_tutor_authentication.html)).
"""
const SSH_AUTH_METHOD_UNKNOWN = Cuint(0)

"""
Auth method enum ([upstream documentation](https://api.libssh.org/stable/libssh_tutor_authentication.html)).
"""
const SSH_AUTH_METHOD_NONE = Cuint(1)

"""
Auth method enum ([upstream documentation](https://api.libssh.org/stable/libssh_tutor_authentication.html)).
"""
const SSH_AUTH_METHOD_PASSWORD = Cuint(2)

"""
Auth method enum ([upstream documentation](https://api.libssh.org/stable/libssh_tutor_authentication.html)).
"""
const SSH_AUTH_METHOD_PUBLICKEY = Cuint(4)

"""
Auth method enum ([upstream documentation](https://api.libssh.org/stable/libssh_tutor_authentication.html)).
"""
const SSH_AUTH_METHOD_HOSTBASED = Cuint(8)

"""
Auth method enum ([upstream documentation](https://api.libssh.org/stable/libssh_tutor_authentication.html)).
"""
const SSH_AUTH_METHOD_INTERACTIVE = Cuint(16)

"""
Auth method enum ([upstream documentation](https://api.libssh.org/stable/libssh_tutor_authentication.html)).
"""
const SSH_AUTH_METHOD_GSSAPI_MIC = Cuint(32)

const SSH_CLOSED = 1

const SSH_READ_PENDING = 2

const SSH_CLOSED_ERROR = 4

const SSH_WRITE_PENDING = 8

const MD5_DIGEST_LEN = 16

const SSH_ADDRSTRLEN = 46

"""
Value returned on success.
"""
const SSH_OK = 0

"""
Value returned if an error occurred.
"""
const SSH_ERROR = -1

"""
Value returned when the function is in non-blocking mode and must be called again.
"""
const SSH_AGAIN = -2

const SSH_EOF = -127

const SSH_LOG_RARE = SSH_LOG_WARNING

const SSH_LOG_NONE = 0

const SSH_LOG_WARN = 1

const SSH_LOG_INFO = 2

const SSH_LOG_DEBUG = 3

const SSH_LOG_TRACE = 4

SSH_VERSION_INT(a, b, c) = (a << 16 | b << 8) | c

SSH_VERSION_DOT(a, b, c) = a

SSH_VERSION(a, b, c) = SSH_VERSION_DOT(a, b, c)

const LIBSSH_VERSION_MAJOR = 0

const LIBSSH_VERSION_MINOR = 11

const LIBSSH_VERSION_MICRO = 1

const LIBSSH_VERSION_INT = SSH_VERSION_INT(LIBSSH_VERSION_MAJOR, LIBSSH_VERSION_MINOR, LIBSSH_VERSION_MICRO)

const LIBSSH_VERSION = SSH_VERSION(LIBSSH_VERSION_MAJOR, LIBSSH_VERSION_MINOR, LIBSSH_VERSION_MICRO)

const LIBSFTP_VERSION = 3

const SSH_FXP_INIT = 1

const SSH_FXP_VERSION = 2

const SSH_FXP_OPEN = 3

const SSH_FXP_CLOSE = 4

const SSH_FXP_READ = 5

const SSH_FXP_WRITE = 6

const SSH_FXP_LSTAT = 7

const SSH_FXP_FSTAT = 8

const SSH_FXP_SETSTAT = 9

const SSH_FXP_FSETSTAT = 10

const SSH_FXP_OPENDIR = 11

const SSH_FXP_READDIR = 12

const SSH_FXP_REMOVE = 13

const SSH_FXP_MKDIR = 14

const SSH_FXP_RMDIR = 15

const SSH_FXP_REALPATH = 16

const SSH_FXP_STAT = 17

const SSH_FXP_RENAME = 18

const SSH_FXP_READLINK = 19

const SSH_FXP_SYMLINK = 20

const SSH_FXP_STATUS = 101

const SSH_FXP_HANDLE = 102

const SSH_FXP_DATA = 103

const SSH_FXP_NAME = 104

const SSH_FXP_ATTRS = 105

const SSH_FXP_EXTENDED = 200

const SSH_FXP_EXTENDED_REPLY = 201

const SSH_FILEXFER_ATTR_SIZE = 1

const SSH_FILEXFER_ATTR_PERMISSIONS = 4

const SSH_FILEXFER_ATTR_ACCESSTIME = 8

const SSH_FILEXFER_ATTR_ACMODTIME = 8

const SSH_FILEXFER_ATTR_CREATETIME = 16

const SSH_FILEXFER_ATTR_MODIFYTIME = 32

const SSH_FILEXFER_ATTR_ACL = 64

const SSH_FILEXFER_ATTR_OWNERGROUP = 128

const SSH_FILEXFER_ATTR_SUBSECOND_TIMES = 256

const SSH_FILEXFER_ATTR_EXTENDED = 2147483648

const SSH_FILEXFER_ATTR_UIDGID = 2

const SSH_FILEXFER_TYPE_REGULAR = 1

const SSH_FILEXFER_TYPE_DIRECTORY = 2

const SSH_FILEXFER_TYPE_SYMLINK = 3

const SSH_FILEXFER_TYPE_SPECIAL = 4

const SSH_FILEXFER_TYPE_UNKNOWN = 5

const SSH_FX_OK = 0

const SSH_FX_EOF = 1

const SSH_FX_NO_SUCH_FILE = 2

const SSH_FX_PERMISSION_DENIED = 3

const SSH_FX_FAILURE = 4

const SSH_FX_BAD_MESSAGE = 5

const SSH_FX_NO_CONNECTION = 6

const SSH_FX_CONNECTION_LOST = 7

const SSH_FX_OP_UNSUPPORTED = 8

const SSH_FX_INVALID_HANDLE = 9

const SSH_FX_NO_SUCH_PATH = 10

const SSH_FX_FILE_ALREADY_EXISTS = 11

const SSH_FX_WRITE_PROTECT = 12

const SSH_FX_NO_MEDIA = 13

const SSH_FXF_READ = 1

const SSH_FXF_WRITE = 2

const SSH_FXF_APPEND = 4

const SSH_FXF_CREAT = 8

const SSH_FXF_TRUNC = 16

const SSH_FXF_EXCL = 32

const SSH_FXF_TEXT = 64

const SSH_S_IFMT = 61440

const SSH_S_IFSOCK = 49152

const SSH_S_IFLNK = 40960

const SSH_S_IFREG = 32768

const SSH_S_IFBLK = 24576

const SSH_S_IFDIR = 16384

const SSH_S_IFCHR = 8192

const SSH_S_IFIFO = 4096

const SSH_FXF_RENAME_OVERWRITE = 1

const SSH_FXF_RENAME_ATOMIC = 2

const SSH_FXF_RENAME_NATIVE = 4

const SFTP_OPEN = SSH_FXP_OPEN

const SFTP_CLOSE = SSH_FXP_CLOSE

const SFTP_READ = SSH_FXP_READ

const SFTP_WRITE = SSH_FXP_WRITE

const SFTP_LSTAT = SSH_FXP_LSTAT

const SFTP_FSTAT = SSH_FXP_FSTAT

const SFTP_SETSTAT = SSH_FXP_SETSTAT

const SFTP_FSETSTAT = SSH_FXP_FSETSTAT

const SFTP_OPENDIR = SSH_FXP_OPENDIR

const SFTP_READDIR = SSH_FXP_READDIR

const SFTP_REMOVE = SSH_FXP_REMOVE

const SFTP_MKDIR = SSH_FXP_MKDIR

const SFTP_RMDIR = SSH_FXP_RMDIR

const SFTP_REALPATH = SSH_FXP_REALPATH

const SFTP_STAT = SSH_FXP_STAT

const SFTP_RENAME = SSH_FXP_RENAME

const SFTP_READLINK = SSH_FXP_READLINK

const SFTP_SYMLINK = SSH_FXP_SYMLINK

const SFTP_EXTENDED = SSH_FXP_EXTENDED

const SSH_FXE_STATVFS_ST_RDONLY = 1

const SSH_FXE_STATVFS_ST_NOSUID = 2

const SSH_SOCKET_FLOW_WRITEWILLBLOCK = 1

const SSH_SOCKET_FLOW_WRITEWONTBLOCK = 2

const SSH_SOCKET_EXCEPTION_EOF = 1

const SSH_SOCKET_EXCEPTION_ERROR = 2

const SSH_SOCKET_CONNECTED_OK = 1

const SSH_SOCKET_CONNECTED_ERROR = 2

const SSH_SOCKET_CONNECTED_TIMEOUT = 3

# Skipping MacroDefinition: ssh_callbacks_init ( p ) do { ( p ) -> size = sizeof ( * ( p ) ) ; \
#} while ( 0 ) ;

const SSH_PACKET_USED = 1

"""
[Upstream documentation](https://api.libssh.org/stable/group__libssh__callbacks.html#ga4766917128a12b646a8aee7ebc019f8c).
"""
const SSH_PACKET_NOT_USED = 2

# Manually wrapped for now until this is merged:
# https://gitlab.com/libssh/libssh-mirror/-/merge_requests/538
function sftp_channel_default_data_callback(session, channel, data, len, is_stderr, userdata)
    @ccall libssh.sftp_channel_default_data_callback(session::ssh_session, channel::ssh_channel, data::Ptr{Cvoid}, len::UInt32, is_stderr::Cint, userdata::Ptr{Cvoid})::Cint
end


# exports
const PREFIXES = ["SSH_LOG_", "SSH_OPTIONS_", "SSH_BIND_OPTIONS_", "SSH_AUTH_", "SSH_KEYTYPE_"]
for name in names(@__MODULE__; all=true), prefix in PREFIXES
    if startswith(string(name), prefix)
        @eval export $name
    end
end

end # module
