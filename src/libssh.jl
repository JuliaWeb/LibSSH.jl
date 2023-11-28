module lib

using CEnum

using libssh_jll


const __uid_t = Cuint

const __gid_t = Cuint

const __mode_t = Cuint

const gid_t = __gid_t

const uid_t = __uid_t

const mode_t = __mode_t

const __fd_mask = Clong

struct fd_set
    __fds_bits::NTuple{16, __fd_mask}
end

const socket_t = Cint

mutable struct ssh_key_struct end

const ssh_key = Ptr{ssh_key_struct}

struct ssh_knownhosts_entry
    hostname::Ptr{Cchar}
    unparsed::Ptr{Cchar}
    publickey::ssh_key
    comment::Ptr{Cchar}
end

function ssh_knownhosts_entry_free(entry)
    ccall((:ssh_knownhosts_entry_free, libssh), Cvoid, (Ptr{ssh_knownhosts_entry},), entry)
end

mutable struct ssh_message_struct end

const ssh_message = Ptr{ssh_message_struct}

function ssh_message_free(msg)
    ccall((:ssh_message_free, libssh), Cvoid, (ssh_message,), msg)
end

function ssh_key_free(key)
    ccall((:ssh_key_free, libssh), Cvoid, (ssh_key,), key)
end

mutable struct ssh_string_struct end

const ssh_string = Ptr{ssh_string_struct}

function ssh_string_free(str)
    ccall((:ssh_string_free, libssh), Cvoid, (ssh_string,), str)
end

function ssh_string_free_char(s)
    ccall((:ssh_string_free_char, libssh), Cvoid, (Ptr{Cchar},), s)
end

mutable struct ssh_buffer_struct end

const ssh_buffer = Ptr{ssh_buffer_struct}

function ssh_buffer_free(buffer)
    ccall((:ssh_buffer_free, libssh), Cvoid, (ssh_buffer,), buffer)
end

struct ssh_counter_struct
    in_bytes::UInt64
    out_bytes::UInt64
    in_packets::UInt64
    out_packets::UInt64
end

const ssh_counter = Ptr{ssh_counter_struct}

mutable struct ssh_agent_struct end

const ssh_agent = Ptr{ssh_agent_struct}

mutable struct ssh_channel_struct end

const ssh_channel = Ptr{ssh_channel_struct}

mutable struct ssh_pcap_file_struct end

const ssh_pcap_file = Ptr{ssh_pcap_file_struct}

mutable struct ssh_scp_struct end

const ssh_scp = Ptr{ssh_scp_struct}

mutable struct ssh_session_struct end

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
end

@cenum var"##Ctag#434"::UInt32 begin
    SSH_LOG_NOLOG = 0
    SSH_LOG_WARNING = 1
    SSH_LOG_PROTOCOL = 2
    SSH_LOG_PACKET = 3
    SSH_LOG_FUNCTIONS = 4
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
end

@cenum var"##Ctag#435"::UInt32 begin
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

function ssh_blocking_flush(session, timeout)
    ccall((:ssh_blocking_flush, libssh), Cint, (ssh_session, Cint), session, timeout)
end

function ssh_channel_accept_x11(channel, timeout_ms)
    ccall((:ssh_channel_accept_x11, libssh), ssh_channel, (ssh_channel, Cint), channel, timeout_ms)
end

function ssh_channel_change_pty_size(channel, cols, rows)
    ccall((:ssh_channel_change_pty_size, libssh), Cint, (ssh_channel, Cint, Cint), channel, cols, rows)
end

function ssh_channel_close(channel)
    ccall((:ssh_channel_close, libssh), Cint, (ssh_channel,), channel)
end

function ssh_channel_free(channel)
    ccall((:ssh_channel_free, libssh), Cvoid, (ssh_channel,), channel)
end

function ssh_channel_get_exit_status(channel)
    ccall((:ssh_channel_get_exit_status, libssh), Cint, (ssh_channel,), channel)
end

function ssh_channel_get_session(channel)
    ccall((:ssh_channel_get_session, libssh), ssh_session, (ssh_channel,), channel)
end

function ssh_channel_is_closed(channel)
    ccall((:ssh_channel_is_closed, libssh), Cint, (ssh_channel,), channel)
end

function ssh_channel_is_eof(channel)
    ccall((:ssh_channel_is_eof, libssh), Cint, (ssh_channel,), channel)
end

function ssh_channel_is_open(channel)
    ccall((:ssh_channel_is_open, libssh), Cint, (ssh_channel,), channel)
end

function ssh_channel_new(session)
    ccall((:ssh_channel_new, libssh), ssh_channel, (ssh_session,), session)
end

function ssh_channel_open_auth_agent(channel)
    ccall((:ssh_channel_open_auth_agent, libssh), Cint, (ssh_channel,), channel)
end

function ssh_channel_open_forward(channel, remotehost, remoteport, sourcehost, localport)
    ccall((:ssh_channel_open_forward, libssh), Cint, (ssh_channel, Ptr{Cchar}, Cint, Ptr{Cchar}, Cint), channel, remotehost, remoteport, sourcehost, localport)
end

function ssh_channel_open_forward_unix(channel, remotepath, sourcehost, localport)
    ccall((:ssh_channel_open_forward_unix, libssh), Cint, (ssh_channel, Ptr{Cchar}, Ptr{Cchar}, Cint), channel, remotepath, sourcehost, localport)
end

function ssh_channel_open_session(channel)
    ccall((:ssh_channel_open_session, libssh), Cint, (ssh_channel,), channel)
end

function ssh_channel_open_x11(channel, orig_addr, orig_port)
    ccall((:ssh_channel_open_x11, libssh), Cint, (ssh_channel, Ptr{Cchar}, Cint), channel, orig_addr, orig_port)
end

function ssh_channel_poll(channel, is_stderr)
    ccall((:ssh_channel_poll, libssh), Cint, (ssh_channel, Cint), channel, is_stderr)
end

function ssh_channel_poll_timeout(channel, timeout, is_stderr)
    ccall((:ssh_channel_poll_timeout, libssh), Cint, (ssh_channel, Cint, Cint), channel, timeout, is_stderr)
end

function ssh_channel_read(channel, dest, count, is_stderr)
    ccall((:ssh_channel_read, libssh), Cint, (ssh_channel, Ptr{Cvoid}, UInt32, Cint), channel, dest, count, is_stderr)
end

function ssh_channel_read_timeout(channel, dest, count, is_stderr, timeout_ms)
    ccall((:ssh_channel_read_timeout, libssh), Cint, (ssh_channel, Ptr{Cvoid}, UInt32, Cint, Cint), channel, dest, count, is_stderr, timeout_ms)
end

function ssh_channel_read_nonblocking(channel, dest, count, is_stderr)
    ccall((:ssh_channel_read_nonblocking, libssh), Cint, (ssh_channel, Ptr{Cvoid}, UInt32, Cint), channel, dest, count, is_stderr)
end

function ssh_channel_request_env(channel, name, value)
    ccall((:ssh_channel_request_env, libssh), Cint, (ssh_channel, Ptr{Cchar}, Ptr{Cchar}), channel, name, value)
end

function ssh_channel_request_exec(channel, cmd)
    ccall((:ssh_channel_request_exec, libssh), Cint, (ssh_channel, Ptr{Cchar}), channel, cmd)
end

function ssh_channel_request_pty(channel)
    ccall((:ssh_channel_request_pty, libssh), Cint, (ssh_channel,), channel)
end

function ssh_channel_request_pty_size(channel, term, cols, rows)
    ccall((:ssh_channel_request_pty_size, libssh), Cint, (ssh_channel, Ptr{Cchar}, Cint, Cint), channel, term, cols, rows)
end

function ssh_channel_request_shell(channel)
    ccall((:ssh_channel_request_shell, libssh), Cint, (ssh_channel,), channel)
end

function ssh_channel_request_send_signal(channel, signum)
    ccall((:ssh_channel_request_send_signal, libssh), Cint, (ssh_channel, Ptr{Cchar}), channel, signum)
end

function ssh_channel_request_send_break(channel, length)
    ccall((:ssh_channel_request_send_break, libssh), Cint, (ssh_channel, UInt32), channel, length)
end

function ssh_channel_request_sftp(channel)
    ccall((:ssh_channel_request_sftp, libssh), Cint, (ssh_channel,), channel)
end

function ssh_channel_request_subsystem(channel, subsystem)
    ccall((:ssh_channel_request_subsystem, libssh), Cint, (ssh_channel, Ptr{Cchar}), channel, subsystem)
end

function ssh_channel_request_x11(channel, single_connection, protocol, cookie, screen_number)
    ccall((:ssh_channel_request_x11, libssh), Cint, (ssh_channel, Cint, Ptr{Cchar}, Ptr{Cchar}, Cint), channel, single_connection, protocol, cookie, screen_number)
end

function ssh_channel_request_auth_agent(channel)
    ccall((:ssh_channel_request_auth_agent, libssh), Cint, (ssh_channel,), channel)
end

function ssh_channel_send_eof(channel)
    ccall((:ssh_channel_send_eof, libssh), Cint, (ssh_channel,), channel)
end

function ssh_channel_set_blocking(channel, blocking)
    ccall((:ssh_channel_set_blocking, libssh), Cvoid, (ssh_channel, Cint), channel, blocking)
end

function ssh_channel_set_counter(channel, counter)
    ccall((:ssh_channel_set_counter, libssh), Cvoid, (ssh_channel, ssh_counter), channel, counter)
end

function ssh_channel_write(channel, data, len)
    ccall((:ssh_channel_write, libssh), Cint, (ssh_channel, Ptr{Cvoid}, UInt32), channel, data, len)
end

function ssh_channel_write_stderr(channel, data, len)
    ccall((:ssh_channel_write_stderr, libssh), Cint, (ssh_channel, Ptr{Cvoid}, UInt32), channel, data, len)
end

function ssh_channel_window_size(channel)
    ccall((:ssh_channel_window_size, libssh), UInt32, (ssh_channel,), channel)
end

function ssh_basename(path)
    ccall((:ssh_basename, libssh), Ptr{Cchar}, (Ptr{Cchar},), path)
end

function ssh_clean_pubkey_hash(hash)
    ccall((:ssh_clean_pubkey_hash, libssh), Cvoid, (Ptr{Ptr{Cuchar}},), hash)
end

function ssh_connect(session)
    ccall((:ssh_connect, libssh), Cint, (ssh_session,), session)
end

function ssh_connector_new(session)
    ccall((:ssh_connector_new, libssh), ssh_connector, (ssh_session,), session)
end

function ssh_connector_free(connector)
    ccall((:ssh_connector_free, libssh), Cvoid, (ssh_connector,), connector)
end

function ssh_connector_set_in_channel(connector, channel, flags)
    ccall((:ssh_connector_set_in_channel, libssh), Cint, (ssh_connector, ssh_channel, ssh_connector_flags_e), connector, channel, flags)
end

function ssh_connector_set_out_channel(connector, channel, flags)
    ccall((:ssh_connector_set_out_channel, libssh), Cint, (ssh_connector, ssh_channel, ssh_connector_flags_e), connector, channel, flags)
end

function ssh_connector_set_in_fd(connector, fd)
    ccall((:ssh_connector_set_in_fd, libssh), Cvoid, (ssh_connector, socket_t), connector, fd)
end

function ssh_connector_set_out_fd(connector, fd)
    ccall((:ssh_connector_set_out_fd, libssh), Cvoid, (ssh_connector, socket_t), connector, fd)
end

function ssh_copyright()
    ccall((:ssh_copyright, libssh), Ptr{Cchar}, ())
end

function ssh_disconnect(session)
    ccall((:ssh_disconnect, libssh), Cvoid, (ssh_session,), session)
end

function ssh_dirname(path)
    ccall((:ssh_dirname, libssh), Ptr{Cchar}, (Ptr{Cchar},), path)
end

function ssh_finalize()
    ccall((:ssh_finalize, libssh), Cint, ())
end

function ssh_channel_open_forward_port(session, timeout_ms, destination_port, originator, originator_port)
    ccall((:ssh_channel_open_forward_port, libssh), ssh_channel, (ssh_session, Cint, Ptr{Cint}, Ptr{Ptr{Cchar}}, Ptr{Cint}), session, timeout_ms, destination_port, originator, originator_port)
end

function ssh_channel_accept_forward(session, timeout_ms, destination_port)
    ccall((:ssh_channel_accept_forward, libssh), ssh_channel, (ssh_session, Cint, Ptr{Cint}), session, timeout_ms, destination_port)
end

function ssh_channel_cancel_forward(session, address, port)
    ccall((:ssh_channel_cancel_forward, libssh), Cint, (ssh_session, Ptr{Cchar}, Cint), session, address, port)
end

function ssh_channel_listen_forward(session, address, port, bound_port)
    ccall((:ssh_channel_listen_forward, libssh), Cint, (ssh_session, Ptr{Cchar}, Cint, Ptr{Cint}), session, address, port, bound_port)
end

function ssh_free(session)
    ccall((:ssh_free, libssh), Cvoid, (ssh_session,), session)
end

function ssh_get_disconnect_message(session)
    ccall((:ssh_get_disconnect_message, libssh), Ptr{Cchar}, (ssh_session,), session)
end

function ssh_get_error(error)
    ccall((:ssh_get_error, libssh), Ptr{Cchar}, (Ptr{Cvoid},), error)
end

function ssh_get_error_code(error)
    ccall((:ssh_get_error_code, libssh), Cint, (Ptr{Cvoid},), error)
end

function ssh_get_fd(session)
    ccall((:ssh_get_fd, libssh), socket_t, (ssh_session,), session)
end

function ssh_get_hexa(what, len)
    ccall((:ssh_get_hexa, libssh), Ptr{Cchar}, (Ptr{Cuchar}, Csize_t), what, len)
end

function ssh_get_issue_banner(session)
    ccall((:ssh_get_issue_banner, libssh), Ptr{Cchar}, (ssh_session,), session)
end

function ssh_get_openssh_version(session)
    ccall((:ssh_get_openssh_version, libssh), Cint, (ssh_session,), session)
end

function ssh_get_server_publickey(session, key)
    ccall((:ssh_get_server_publickey, libssh), Cint, (ssh_session, Ptr{ssh_key}), session, key)
end

@cenum ssh_publickey_hash_type::UInt32 begin
    SSH_PUBLICKEY_HASH_SHA1 = 0
    SSH_PUBLICKEY_HASH_MD5 = 1
    SSH_PUBLICKEY_HASH_SHA256 = 2
end

function ssh_get_publickey_hash(key, type, hash, hlen)
    ccall((:ssh_get_publickey_hash, libssh), Cint, (ssh_key, ssh_publickey_hash_type, Ptr{Ptr{Cuchar}}, Ptr{Csize_t}), key, type, hash, hlen)
end

function ssh_get_pubkey_hash(session, hash)
    ccall((:ssh_get_pubkey_hash, libssh), Cint, (ssh_session, Ptr{Ptr{Cuchar}}), session, hash)
end

function ssh_forward_accept(session, timeout_ms)
    ccall((:ssh_forward_accept, libssh), ssh_channel, (ssh_session, Cint), session, timeout_ms)
end

function ssh_forward_cancel(session, address, port)
    ccall((:ssh_forward_cancel, libssh), Cint, (ssh_session, Ptr{Cchar}, Cint), session, address, port)
end

function ssh_forward_listen(session, address, port, bound_port)
    ccall((:ssh_forward_listen, libssh), Cint, (ssh_session, Ptr{Cchar}, Cint, Ptr{Cint}), session, address, port, bound_port)
end

function ssh_get_publickey(session, key)
    ccall((:ssh_get_publickey, libssh), Cint, (ssh_session, Ptr{ssh_key}), session, key)
end

function ssh_write_knownhost(session)
    ccall((:ssh_write_knownhost, libssh), Cint, (ssh_session,), session)
end

function ssh_dump_knownhost(session)
    ccall((:ssh_dump_knownhost, libssh), Ptr{Cchar}, (ssh_session,), session)
end

function ssh_is_server_known(session)
    ccall((:ssh_is_server_known, libssh), Cint, (ssh_session,), session)
end

function ssh_print_hexa(descr, what, len)
    ccall((:ssh_print_hexa, libssh), Cvoid, (Ptr{Cchar}, Ptr{Cuchar}, Csize_t), descr, what, len)
end

function ssh_channel_select(readchans, writechans, exceptchans, timeout)
    ccall((:ssh_channel_select, libssh), Cint, (Ptr{ssh_channel}, Ptr{ssh_channel}, Ptr{ssh_channel}, Ptr{Cvoid}), readchans, writechans, exceptchans, timeout)
end

function ssh_scp_accept_request(scp)
    ccall((:ssh_scp_accept_request, libssh), Cint, (ssh_scp,), scp)
end

function ssh_scp_close(scp)
    ccall((:ssh_scp_close, libssh), Cint, (ssh_scp,), scp)
end

function ssh_scp_deny_request(scp, reason)
    ccall((:ssh_scp_deny_request, libssh), Cint, (ssh_scp, Ptr{Cchar}), scp, reason)
end

function ssh_scp_free(scp)
    ccall((:ssh_scp_free, libssh), Cvoid, (ssh_scp,), scp)
end

function ssh_scp_init(scp)
    ccall((:ssh_scp_init, libssh), Cint, (ssh_scp,), scp)
end

function ssh_scp_leave_directory(scp)
    ccall((:ssh_scp_leave_directory, libssh), Cint, (ssh_scp,), scp)
end

function ssh_scp_new(session, mode, location)
    ccall((:ssh_scp_new, libssh), ssh_scp, (ssh_session, Cint, Ptr{Cchar}), session, mode, location)
end

function ssh_scp_pull_request(scp)
    ccall((:ssh_scp_pull_request, libssh), Cint, (ssh_scp,), scp)
end

function ssh_scp_push_directory(scp, dirname, mode)
    ccall((:ssh_scp_push_directory, libssh), Cint, (ssh_scp, Ptr{Cchar}, Cint), scp, dirname, mode)
end

function ssh_scp_push_file(scp, filename, size, perms)
    ccall((:ssh_scp_push_file, libssh), Cint, (ssh_scp, Ptr{Cchar}, Csize_t, Cint), scp, filename, size, perms)
end

function ssh_scp_push_file64(scp, filename, size, perms)
    ccall((:ssh_scp_push_file64, libssh), Cint, (ssh_scp, Ptr{Cchar}, UInt64, Cint), scp, filename, size, perms)
end

function ssh_scp_read(scp, buffer, size)
    ccall((:ssh_scp_read, libssh), Cint, (ssh_scp, Ptr{Cvoid}, Csize_t), scp, buffer, size)
end

function ssh_scp_request_get_filename(scp)
    ccall((:ssh_scp_request_get_filename, libssh), Ptr{Cchar}, (ssh_scp,), scp)
end

function ssh_scp_request_get_permissions(scp)
    ccall((:ssh_scp_request_get_permissions, libssh), Cint, (ssh_scp,), scp)
end

function ssh_scp_request_get_size(scp)
    ccall((:ssh_scp_request_get_size, libssh), Csize_t, (ssh_scp,), scp)
end

function ssh_scp_request_get_size64(scp)
    ccall((:ssh_scp_request_get_size64, libssh), UInt64, (ssh_scp,), scp)
end

function ssh_scp_request_get_warning(scp)
    ccall((:ssh_scp_request_get_warning, libssh), Ptr{Cchar}, (ssh_scp,), scp)
end

function ssh_scp_write(scp, buffer, len)
    ccall((:ssh_scp_write, libssh), Cint, (ssh_scp, Ptr{Cvoid}, Csize_t), scp, buffer, len)
end

function ssh_get_random(where, len, strong)
    ccall((:ssh_get_random, libssh), Cint, (Ptr{Cvoid}, Cint, Cint), where, len, strong)
end

function ssh_get_version(session)
    ccall((:ssh_get_version, libssh), Cint, (ssh_session,), session)
end

function ssh_get_status(session)
    ccall((:ssh_get_status, libssh), Cint, (ssh_session,), session)
end

function ssh_get_poll_flags(session)
    ccall((:ssh_get_poll_flags, libssh), Cint, (ssh_session,), session)
end

function ssh_init()
    ccall((:ssh_init, libssh), Cint, ())
end

function ssh_is_blocking(session)
    ccall((:ssh_is_blocking, libssh), Cint, (ssh_session,), session)
end

function ssh_is_connected(session)
    ccall((:ssh_is_connected, libssh), Cint, (ssh_session,), session)
end

function ssh_known_hosts_parse_line(host, line, entry)
    ccall((:ssh_known_hosts_parse_line, libssh), Cint, (Ptr{Cchar}, Ptr{Cchar}, Ptr{Ptr{ssh_knownhosts_entry}}), host, line, entry)
end

function ssh_session_has_known_hosts_entry(session)
    ccall((:ssh_session_has_known_hosts_entry, libssh), ssh_known_hosts_e, (ssh_session,), session)
end

function ssh_session_export_known_hosts_entry(session, pentry_string)
    ccall((:ssh_session_export_known_hosts_entry, libssh), Cint, (ssh_session, Ptr{Ptr{Cchar}}), session, pentry_string)
end

function ssh_session_update_known_hosts(session)
    ccall((:ssh_session_update_known_hosts, libssh), Cint, (ssh_session,), session)
end

function ssh_session_get_known_hosts_entry(session, pentry)
    ccall((:ssh_session_get_known_hosts_entry, libssh), ssh_known_hosts_e, (ssh_session, Ptr{Ptr{ssh_knownhosts_entry}}), session, pentry)
end

function ssh_session_is_known_server(session)
    ccall((:ssh_session_is_known_server, libssh), ssh_known_hosts_e, (ssh_session,), session)
end

function ssh_set_log_level(level)
    ccall((:ssh_set_log_level, libssh), Cint, (Cint,), level)
end

function ssh_get_log_level()
    ccall((:ssh_get_log_level, libssh), Cint, ())
end

function ssh_get_log_userdata()
    ccall((:ssh_get_log_userdata, libssh), Ptr{Cvoid}, ())
end

function ssh_set_log_userdata(data)
    ccall((:ssh_set_log_userdata, libssh), Cint, (Ptr{Cvoid},), data)
end

function ssh_message_channel_request_open_reply_accept(msg)
    ccall((:ssh_message_channel_request_open_reply_accept, libssh), ssh_channel, (ssh_message,), msg)
end

function ssh_message_channel_request_open_reply_accept_channel(msg, chan)
    ccall((:ssh_message_channel_request_open_reply_accept_channel, libssh), Cint, (ssh_message, ssh_channel), msg, chan)
end

function ssh_message_channel_request_reply_success(msg)
    ccall((:ssh_message_channel_request_reply_success, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_get(session)
    ccall((:ssh_message_get, libssh), ssh_message, (ssh_session,), session)
end

function ssh_message_subtype(msg)
    ccall((:ssh_message_subtype, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_type(msg)
    ccall((:ssh_message_type, libssh), Cint, (ssh_message,), msg)
end

function ssh_mkdir(pathname, mode)
    ccall((:ssh_mkdir, libssh), Cint, (Ptr{Cchar}, mode_t), pathname, mode)
end

function ssh_new()
    ccall((:ssh_new, libssh), ssh_session, ())
end

function ssh_options_copy(src, dest)
    ccall((:ssh_options_copy, libssh), Cint, (ssh_session, Ptr{ssh_session}), src, dest)
end

function ssh_options_getopt(session, argcptr, argv)
    ccall((:ssh_options_getopt, libssh), Cint, (ssh_session, Ptr{Cint}, Ptr{Ptr{Cchar}}), session, argcptr, argv)
end

function ssh_options_parse_config(session, filename)
    ccall((:ssh_options_parse_config, libssh), Cint, (ssh_session, Ptr{Cchar}), session, filename)
end

function ssh_options_set(session, type, value)
    ccall((:ssh_options_set, libssh), Cint, (ssh_session, ssh_options_e, Ptr{Cvoid}), session, type, value)
end

function ssh_options_get(session, type, value)
    ccall((:ssh_options_get, libssh), Cint, (ssh_session, ssh_options_e, Ptr{Ptr{Cchar}}), session, type, value)
end

function ssh_options_get_port(session, port_target)
    ccall((:ssh_options_get_port, libssh), Cint, (ssh_session, Ptr{Cuint}), session, port_target)
end

function ssh_pcap_file_close(pcap)
    ccall((:ssh_pcap_file_close, libssh), Cint, (ssh_pcap_file,), pcap)
end

function ssh_pcap_file_free(pcap)
    ccall((:ssh_pcap_file_free, libssh), Cvoid, (ssh_pcap_file,), pcap)
end

function ssh_pcap_file_new()
    ccall((:ssh_pcap_file_new, libssh), ssh_pcap_file, ())
end

function ssh_pcap_file_open(pcap, filename)
    ccall((:ssh_pcap_file_open, libssh), Cint, (ssh_pcap_file, Ptr{Cchar}), pcap, filename)
end

# typedef int ( * ssh_auth_callback ) ( const char * prompt , char * buf , size_t len , int echo , int verify , void * userdata )
const ssh_auth_callback = Ptr{Cvoid}

function ssh_key_new()
    ccall((:ssh_key_new, libssh), ssh_key, ())
end

function ssh_key_type(key)
    ccall((:ssh_key_type, libssh), ssh_keytypes_e, (ssh_key,), key)
end

function ssh_key_type_to_char(type)
    ccall((:ssh_key_type_to_char, libssh), Ptr{Cchar}, (ssh_keytypes_e,), type)
end

function ssh_key_type_from_name(name)
    ccall((:ssh_key_type_from_name, libssh), ssh_keytypes_e, (Ptr{Cchar},), name)
end

function ssh_key_is_public(k)
    ccall((:ssh_key_is_public, libssh), Cint, (ssh_key,), k)
end

function ssh_key_is_private(k)
    ccall((:ssh_key_is_private, libssh), Cint, (ssh_key,), k)
end

function ssh_key_cmp(k1, k2, what)
    ccall((:ssh_key_cmp, libssh), Cint, (ssh_key, ssh_key, ssh_keycmp_e), k1, k2, what)
end

function ssh_key_dup(key)
    ccall((:ssh_key_dup, libssh), ssh_key, (ssh_key,), key)
end

function ssh_pki_generate(type, parameter, pkey)
    ccall((:ssh_pki_generate, libssh), Cint, (ssh_keytypes_e, Cint, Ptr{ssh_key}), type, parameter, pkey)
end

function ssh_pki_import_privkey_base64(b64_key, passphrase, auth_fn, auth_data, pkey)
    ccall((:ssh_pki_import_privkey_base64, libssh), Cint, (Ptr{Cchar}, Ptr{Cchar}, ssh_auth_callback, Ptr{Cvoid}, Ptr{ssh_key}), b64_key, passphrase, auth_fn, auth_data, pkey)
end

function ssh_pki_export_privkey_base64(privkey, passphrase, auth_fn, auth_data, b64_key)
    ccall((:ssh_pki_export_privkey_base64, libssh), Cint, (ssh_key, Ptr{Cchar}, ssh_auth_callback, Ptr{Cvoid}, Ptr{Ptr{Cchar}}), privkey, passphrase, auth_fn, auth_data, b64_key)
end

function ssh_pki_import_privkey_file(filename, passphrase, auth_fn, auth_data, pkey)
    ccall((:ssh_pki_import_privkey_file, libssh), Cint, (Ptr{Cchar}, Ptr{Cchar}, ssh_auth_callback, Ptr{Cvoid}, Ptr{ssh_key}), filename, passphrase, auth_fn, auth_data, pkey)
end

function ssh_pki_export_privkey_file(privkey, passphrase, auth_fn, auth_data, filename)
    ccall((:ssh_pki_export_privkey_file, libssh), Cint, (ssh_key, Ptr{Cchar}, ssh_auth_callback, Ptr{Cvoid}, Ptr{Cchar}), privkey, passphrase, auth_fn, auth_data, filename)
end

function ssh_pki_copy_cert_to_privkey(cert_key, privkey)
    ccall((:ssh_pki_copy_cert_to_privkey, libssh), Cint, (ssh_key, ssh_key), cert_key, privkey)
end

function ssh_pki_import_pubkey_base64(b64_key, type, pkey)
    ccall((:ssh_pki_import_pubkey_base64, libssh), Cint, (Ptr{Cchar}, ssh_keytypes_e, Ptr{ssh_key}), b64_key, type, pkey)
end

function ssh_pki_import_pubkey_file(filename, pkey)
    ccall((:ssh_pki_import_pubkey_file, libssh), Cint, (Ptr{Cchar}, Ptr{ssh_key}), filename, pkey)
end

function ssh_pki_import_cert_base64(b64_cert, type, pkey)
    ccall((:ssh_pki_import_cert_base64, libssh), Cint, (Ptr{Cchar}, ssh_keytypes_e, Ptr{ssh_key}), b64_cert, type, pkey)
end

function ssh_pki_import_cert_file(filename, pkey)
    ccall((:ssh_pki_import_cert_file, libssh), Cint, (Ptr{Cchar}, Ptr{ssh_key}), filename, pkey)
end

function ssh_pki_export_privkey_to_pubkey(privkey, pkey)
    ccall((:ssh_pki_export_privkey_to_pubkey, libssh), Cint, (ssh_key, Ptr{ssh_key}), privkey, pkey)
end

function ssh_pki_export_pubkey_base64(key, b64_key)
    ccall((:ssh_pki_export_pubkey_base64, libssh), Cint, (ssh_key, Ptr{Ptr{Cchar}}), key, b64_key)
end

function ssh_pki_export_pubkey_file(key, filename)
    ccall((:ssh_pki_export_pubkey_file, libssh), Cint, (ssh_key, Ptr{Cchar}), key, filename)
end

function ssh_pki_key_ecdsa_name(key)
    ccall((:ssh_pki_key_ecdsa_name, libssh), Ptr{Cchar}, (ssh_key,), key)
end

function ssh_get_fingerprint_hash(type, hash, len)
    ccall((:ssh_get_fingerprint_hash, libssh), Ptr{Cchar}, (ssh_publickey_hash_type, Ptr{Cuchar}, Csize_t), type, hash, len)
end

function ssh_print_hash(type, hash, len)
    ccall((:ssh_print_hash, libssh), Cvoid, (ssh_publickey_hash_type, Ptr{Cuchar}, Csize_t), type, hash, len)
end

function ssh_send_ignore(session, data)
    ccall((:ssh_send_ignore, libssh), Cint, (ssh_session, Ptr{Cchar}), session, data)
end

function ssh_send_debug(session, message, always_display)
    ccall((:ssh_send_debug, libssh), Cint, (ssh_session, Ptr{Cchar}, Cint), session, message, always_display)
end

function ssh_gssapi_set_creds(session, creds)
    ccall((:ssh_gssapi_set_creds, libssh), Cvoid, (ssh_session, ssh_gssapi_creds), session, creds)
end

function ssh_select(channels, outchannels, maxfd, readfds, timeout)
    ccall((:ssh_select, libssh), Cint, (Ptr{ssh_channel}, Ptr{ssh_channel}, socket_t, Ptr{fd_set}, Ptr{Cvoid}), channels, outchannels, maxfd, readfds, timeout)
end

function ssh_service_request(session, service)
    ccall((:ssh_service_request, libssh), Cint, (ssh_session, Ptr{Cchar}), session, service)
end

function ssh_set_agent_channel(session, channel)
    ccall((:ssh_set_agent_channel, libssh), Cint, (ssh_session, ssh_channel), session, channel)
end

function ssh_set_agent_socket(session, fd)
    ccall((:ssh_set_agent_socket, libssh), Cint, (ssh_session, socket_t), session, fd)
end

function ssh_set_blocking(session, blocking)
    ccall((:ssh_set_blocking, libssh), Cvoid, (ssh_session, Cint), session, blocking)
end

function ssh_set_counters(session, scounter, rcounter)
    ccall((:ssh_set_counters, libssh), Cvoid, (ssh_session, ssh_counter, ssh_counter), session, scounter, rcounter)
end

function ssh_set_fd_except(session)
    ccall((:ssh_set_fd_except, libssh), Cvoid, (ssh_session,), session)
end

function ssh_set_fd_toread(session)
    ccall((:ssh_set_fd_toread, libssh), Cvoid, (ssh_session,), session)
end

function ssh_set_fd_towrite(session)
    ccall((:ssh_set_fd_towrite, libssh), Cvoid, (ssh_session,), session)
end

function ssh_silent_disconnect(session)
    ccall((:ssh_silent_disconnect, libssh), Cvoid, (ssh_session,), session)
end

function ssh_set_pcap_file(session, pcapfile)
    ccall((:ssh_set_pcap_file, libssh), Cint, (ssh_session, ssh_pcap_file), session, pcapfile)
end

function ssh_userauth_none(session, username)
    ccall((:ssh_userauth_none, libssh), Cint, (ssh_session, Ptr{Cchar}), session, username)
end

function ssh_userauth_list(session, username)
    ccall((:ssh_userauth_list, libssh), Cint, (ssh_session, Ptr{Cchar}), session, username)
end

function ssh_userauth_try_publickey(session, username, pubkey)
    ccall((:ssh_userauth_try_publickey, libssh), Cint, (ssh_session, Ptr{Cchar}, ssh_key), session, username, pubkey)
end

function ssh_userauth_publickey(session, username, privkey)
    ccall((:ssh_userauth_publickey, libssh), Cint, (ssh_session, Ptr{Cchar}, ssh_key), session, username, privkey)
end

function ssh_userauth_agent(session, username)
    ccall((:ssh_userauth_agent, libssh), Cint, (ssh_session, Ptr{Cchar}), session, username)
end

function ssh_userauth_publickey_auto_get_current_identity(session, value)
    ccall((:ssh_userauth_publickey_auto_get_current_identity, libssh), Cint, (ssh_session, Ptr{Ptr{Cchar}}), session, value)
end

function ssh_userauth_publickey_auto(session, username, passphrase)
    ccall((:ssh_userauth_publickey_auto, libssh), Cint, (ssh_session, Ptr{Cchar}, Ptr{Cchar}), session, username, passphrase)
end

function ssh_userauth_password(session, username, password)
    ccall((:ssh_userauth_password, libssh), Cint, (ssh_session, Ptr{Cchar}, Ptr{Cchar}), session, username, password)
end

function ssh_userauth_kbdint(session, user, submethods)
    ccall((:ssh_userauth_kbdint, libssh), Cint, (ssh_session, Ptr{Cchar}, Ptr{Cchar}), session, user, submethods)
end

function ssh_userauth_kbdint_getinstruction(session)
    ccall((:ssh_userauth_kbdint_getinstruction, libssh), Ptr{Cchar}, (ssh_session,), session)
end

function ssh_userauth_kbdint_getname(session)
    ccall((:ssh_userauth_kbdint_getname, libssh), Ptr{Cchar}, (ssh_session,), session)
end

function ssh_userauth_kbdint_getnprompts(session)
    ccall((:ssh_userauth_kbdint_getnprompts, libssh), Cint, (ssh_session,), session)
end

function ssh_userauth_kbdint_getprompt(session, i, echo)
    ccall((:ssh_userauth_kbdint_getprompt, libssh), Ptr{Cchar}, (ssh_session, Cuint, Ptr{Cchar}), session, i, echo)
end

function ssh_userauth_kbdint_getnanswers(session)
    ccall((:ssh_userauth_kbdint_getnanswers, libssh), Cint, (ssh_session,), session)
end

function ssh_userauth_kbdint_getanswer(session, i)
    ccall((:ssh_userauth_kbdint_getanswer, libssh), Ptr{Cchar}, (ssh_session, Cuint), session, i)
end

function ssh_userauth_kbdint_setanswer(session, i, answer)
    ccall((:ssh_userauth_kbdint_setanswer, libssh), Cint, (ssh_session, Cuint, Ptr{Cchar}), session, i, answer)
end

function ssh_userauth_gssapi(session)
    ccall((:ssh_userauth_gssapi, libssh), Cint, (ssh_session,), session)
end

function ssh_version(req_version)
    ccall((:ssh_version, libssh), Ptr{Cchar}, (Cint,), req_version)
end

function ssh_string_burn(str)
    ccall((:ssh_string_burn, libssh), Cvoid, (ssh_string,), str)
end

function ssh_string_copy(str)
    ccall((:ssh_string_copy, libssh), ssh_string, (ssh_string,), str)
end

function ssh_string_data(str)
    ccall((:ssh_string_data, libssh), Ptr{Cvoid}, (ssh_string,), str)
end

function ssh_string_fill(str, data, len)
    ccall((:ssh_string_fill, libssh), Cint, (ssh_string, Ptr{Cvoid}, Csize_t), str, data, len)
end

function ssh_string_from_char(what)
    ccall((:ssh_string_from_char, libssh), ssh_string, (Ptr{Cchar},), what)
end

function ssh_string_len(str)
    ccall((:ssh_string_len, libssh), Csize_t, (ssh_string,), str)
end

function ssh_string_new(size)
    ccall((:ssh_string_new, libssh), ssh_string, (Csize_t,), size)
end

function ssh_string_get_char(str)
    ccall((:ssh_string_get_char, libssh), Ptr{Cchar}, (ssh_string,), str)
end

function ssh_string_to_char(str)
    ccall((:ssh_string_to_char, libssh), Ptr{Cchar}, (ssh_string,), str)
end

function ssh_getpass(prompt, buf, len, echo, verify)
    ccall((:ssh_getpass, libssh), Cint, (Ptr{Cchar}, Ptr{Cchar}, Csize_t, Cint, Cint), prompt, buf, len, echo, verify)
end

# typedef int ( * ssh_event_callback ) ( socket_t fd , int revents , void * userdata )
const ssh_event_callback = Ptr{Cvoid}

function ssh_event_new()
    ccall((:ssh_event_new, libssh), ssh_event, ())
end

function ssh_event_add_fd(event, fd, events, cb, userdata)
    ccall((:ssh_event_add_fd, libssh), Cint, (ssh_event, socket_t, Cshort, ssh_event_callback, Ptr{Cvoid}), event, fd, events, cb, userdata)
end

function ssh_event_add_session(event, session)
    ccall((:ssh_event_add_session, libssh), Cint, (ssh_event, ssh_session), event, session)
end

function ssh_event_add_connector(event, connector)
    ccall((:ssh_event_add_connector, libssh), Cint, (ssh_event, ssh_connector), event, connector)
end

function ssh_event_dopoll(event, timeout)
    ccall((:ssh_event_dopoll, libssh), Cint, (ssh_event, Cint), event, timeout)
end

function ssh_event_remove_fd(event, fd)
    ccall((:ssh_event_remove_fd, libssh), Cint, (ssh_event, socket_t), event, fd)
end

function ssh_event_remove_session(event, session)
    ccall((:ssh_event_remove_session, libssh), Cint, (ssh_event, ssh_session), event, session)
end

function ssh_event_remove_connector(event, connector)
    ccall((:ssh_event_remove_connector, libssh), Cint, (ssh_event, ssh_connector), event, connector)
end

function ssh_event_free(event)
    ccall((:ssh_event_free, libssh), Cvoid, (ssh_event,), event)
end

function ssh_get_clientbanner(session)
    ccall((:ssh_get_clientbanner, libssh), Ptr{Cchar}, (ssh_session,), session)
end

function ssh_get_serverbanner(session)
    ccall((:ssh_get_serverbanner, libssh), Ptr{Cchar}, (ssh_session,), session)
end

function ssh_get_kex_algo(session)
    ccall((:ssh_get_kex_algo, libssh), Ptr{Cchar}, (ssh_session,), session)
end

function ssh_get_cipher_in(session)
    ccall((:ssh_get_cipher_in, libssh), Ptr{Cchar}, (ssh_session,), session)
end

function ssh_get_cipher_out(session)
    ccall((:ssh_get_cipher_out, libssh), Ptr{Cchar}, (ssh_session,), session)
end

function ssh_get_hmac_in(session)
    ccall((:ssh_get_hmac_in, libssh), Ptr{Cchar}, (ssh_session,), session)
end

function ssh_get_hmac_out(session)
    ccall((:ssh_get_hmac_out, libssh), Ptr{Cchar}, (ssh_session,), session)
end

function ssh_buffer_new()
    ccall((:ssh_buffer_new, libssh), ssh_buffer, ())
end

function ssh_buffer_reinit(buffer)
    ccall((:ssh_buffer_reinit, libssh), Cint, (ssh_buffer,), buffer)
end

function ssh_buffer_add_data(buffer, data, len)
    ccall((:ssh_buffer_add_data, libssh), Cint, (ssh_buffer, Ptr{Cvoid}, UInt32), buffer, data, len)
end

function ssh_buffer_get_data(buffer, data, requestedlen)
    ccall((:ssh_buffer_get_data, libssh), UInt32, (ssh_buffer, Ptr{Cvoid}, UInt32), buffer, data, requestedlen)
end

function ssh_buffer_get(buffer)
    ccall((:ssh_buffer_get, libssh), Ptr{Cvoid}, (ssh_buffer,), buffer)
end

function ssh_buffer_get_len(buffer)
    ccall((:ssh_buffer_get_len, libssh), UInt32, (ssh_buffer,), buffer)
end

function ssh_session_set_disconnect_message(session, message)
    ccall((:ssh_session_set_disconnect_message, libssh), Cint, (ssh_session, Ptr{Cchar}), session, message)
end

mutable struct ssh_private_key_struct end

const ssh_private_key = Ptr{ssh_private_key_struct}

mutable struct ssh_public_key_struct end

const ssh_public_key = Ptr{ssh_public_key_struct}

function ssh_auth_list(session)
    ccall((:ssh_auth_list, libssh), Cint, (ssh_session,), session)
end

function ssh_userauth_offer_pubkey(session, username, type, publickey)
    ccall((:ssh_userauth_offer_pubkey, libssh), Cint, (ssh_session, Ptr{Cchar}, Cint, ssh_string), session, username, type, publickey)
end

function ssh_userauth_pubkey(session, username, publickey, privatekey)
    ccall((:ssh_userauth_pubkey, libssh), Cint, (ssh_session, Ptr{Cchar}, ssh_string, ssh_private_key), session, username, publickey, privatekey)
end

function ssh_userauth_agent_pubkey(session, username, publickey)
    ccall((:ssh_userauth_agent_pubkey, libssh), Cint, (ssh_session, Ptr{Cchar}, ssh_public_key), session, username, publickey)
end

function ssh_userauth_autopubkey(session, passphrase)
    ccall((:ssh_userauth_autopubkey, libssh), Cint, (ssh_session, Ptr{Cchar}), session, passphrase)
end

function ssh_userauth_privatekey_file(session, username, filename, passphrase)
    ccall((:ssh_userauth_privatekey_file, libssh), Cint, (ssh_session, Ptr{Cchar}, Ptr{Cchar}, Ptr{Cchar}), session, username, filename, passphrase)
end

function buffer_free(buffer)
    ccall((:buffer_free, libssh), Cvoid, (ssh_buffer,), buffer)
end

function buffer_get(buffer)
    ccall((:buffer_get, libssh), Ptr{Cvoid}, (ssh_buffer,), buffer)
end

function buffer_get_len(buffer)
    ccall((:buffer_get_len, libssh), UInt32, (ssh_buffer,), buffer)
end

function buffer_new()
    ccall((:buffer_new, libssh), ssh_buffer, ())
end

function channel_accept_x11(channel, timeout_ms)
    ccall((:channel_accept_x11, libssh), ssh_channel, (ssh_channel, Cint), channel, timeout_ms)
end

function channel_change_pty_size(channel, cols, rows)
    ccall((:channel_change_pty_size, libssh), Cint, (ssh_channel, Cint, Cint), channel, cols, rows)
end

function channel_forward_accept(session, timeout_ms)
    ccall((:channel_forward_accept, libssh), ssh_channel, (ssh_session, Cint), session, timeout_ms)
end

function channel_close(channel)
    ccall((:channel_close, libssh), Cint, (ssh_channel,), channel)
end

function channel_forward_cancel(session, address, port)
    ccall((:channel_forward_cancel, libssh), Cint, (ssh_session, Ptr{Cchar}, Cint), session, address, port)
end

function channel_forward_listen(session, address, port, bound_port)
    ccall((:channel_forward_listen, libssh), Cint, (ssh_session, Ptr{Cchar}, Cint, Ptr{Cint}), session, address, port, bound_port)
end

function channel_free(channel)
    ccall((:channel_free, libssh), Cvoid, (ssh_channel,), channel)
end

function channel_get_exit_status(channel)
    ccall((:channel_get_exit_status, libssh), Cint, (ssh_channel,), channel)
end

function channel_get_session(channel)
    ccall((:channel_get_session, libssh), ssh_session, (ssh_channel,), channel)
end

function channel_is_closed(channel)
    ccall((:channel_is_closed, libssh), Cint, (ssh_channel,), channel)
end

function channel_is_eof(channel)
    ccall((:channel_is_eof, libssh), Cint, (ssh_channel,), channel)
end

function channel_is_open(channel)
    ccall((:channel_is_open, libssh), Cint, (ssh_channel,), channel)
end

function channel_new(session)
    ccall((:channel_new, libssh), ssh_channel, (ssh_session,), session)
end

function channel_open_forward(channel, remotehost, remoteport, sourcehost, localport)
    ccall((:channel_open_forward, libssh), Cint, (ssh_channel, Ptr{Cchar}, Cint, Ptr{Cchar}, Cint), channel, remotehost, remoteport, sourcehost, localport)
end

function channel_open_session(channel)
    ccall((:channel_open_session, libssh), Cint, (ssh_channel,), channel)
end

function channel_poll(channel, is_stderr)
    ccall((:channel_poll, libssh), Cint, (ssh_channel, Cint), channel, is_stderr)
end

function channel_read(channel, dest, count, is_stderr)
    ccall((:channel_read, libssh), Cint, (ssh_channel, Ptr{Cvoid}, UInt32, Cint), channel, dest, count, is_stderr)
end

function channel_read_buffer(channel, buffer, count, is_stderr)
    ccall((:channel_read_buffer, libssh), Cint, (ssh_channel, ssh_buffer, UInt32, Cint), channel, buffer, count, is_stderr)
end

function channel_read_nonblocking(channel, dest, count, is_stderr)
    ccall((:channel_read_nonblocking, libssh), Cint, (ssh_channel, Ptr{Cvoid}, UInt32, Cint), channel, dest, count, is_stderr)
end

function channel_request_env(channel, name, value)
    ccall((:channel_request_env, libssh), Cint, (ssh_channel, Ptr{Cchar}, Ptr{Cchar}), channel, name, value)
end

function channel_request_exec(channel, cmd)
    ccall((:channel_request_exec, libssh), Cint, (ssh_channel, Ptr{Cchar}), channel, cmd)
end

function channel_request_pty(channel)
    ccall((:channel_request_pty, libssh), Cint, (ssh_channel,), channel)
end

function channel_request_pty_size(channel, term, cols, rows)
    ccall((:channel_request_pty_size, libssh), Cint, (ssh_channel, Ptr{Cchar}, Cint, Cint), channel, term, cols, rows)
end

function channel_request_shell(channel)
    ccall((:channel_request_shell, libssh), Cint, (ssh_channel,), channel)
end

function channel_request_send_signal(channel, signum)
    ccall((:channel_request_send_signal, libssh), Cint, (ssh_channel, Ptr{Cchar}), channel, signum)
end

function channel_request_sftp(channel)
    ccall((:channel_request_sftp, libssh), Cint, (ssh_channel,), channel)
end

function channel_request_subsystem(channel, subsystem)
    ccall((:channel_request_subsystem, libssh), Cint, (ssh_channel, Ptr{Cchar}), channel, subsystem)
end

function channel_request_x11(channel, single_connection, protocol, cookie, screen_number)
    ccall((:channel_request_x11, libssh), Cint, (ssh_channel, Cint, Ptr{Cchar}, Ptr{Cchar}, Cint), channel, single_connection, protocol, cookie, screen_number)
end

function channel_send_eof(channel)
    ccall((:channel_send_eof, libssh), Cint, (ssh_channel,), channel)
end

function channel_select(readchans, writechans, exceptchans, timeout)
    ccall((:channel_select, libssh), Cint, (Ptr{ssh_channel}, Ptr{ssh_channel}, Ptr{ssh_channel}, Ptr{Cvoid}), readchans, writechans, exceptchans, timeout)
end

function channel_set_blocking(channel, blocking)
    ccall((:channel_set_blocking, libssh), Cvoid, (ssh_channel, Cint), channel, blocking)
end

function channel_write(channel, data, len)
    ccall((:channel_write, libssh), Cint, (ssh_channel, Ptr{Cvoid}, UInt32), channel, data, len)
end

function privatekey_free(prv)
    ccall((:privatekey_free, libssh), Cvoid, (ssh_private_key,), prv)
end

function privatekey_from_file(session, filename, type, passphrase)
    ccall((:privatekey_from_file, libssh), ssh_private_key, (ssh_session, Ptr{Cchar}, Cint, Ptr{Cchar}), session, filename, type, passphrase)
end

function publickey_free(key)
    ccall((:publickey_free, libssh), Cvoid, (ssh_public_key,), key)
end

function ssh_publickey_to_file(session, file, pubkey, type)
    ccall((:ssh_publickey_to_file, libssh), Cint, (ssh_session, Ptr{Cchar}, ssh_string, Cint), session, file, pubkey, type)
end

function publickey_from_file(session, filename, type)
    ccall((:publickey_from_file, libssh), ssh_string, (ssh_session, Ptr{Cchar}, Ptr{Cint}), session, filename, type)
end

function publickey_from_privatekey(prv)
    ccall((:publickey_from_privatekey, libssh), ssh_public_key, (ssh_private_key,), prv)
end

function publickey_to_string(key)
    ccall((:publickey_to_string, libssh), ssh_string, (ssh_public_key,), key)
end

function ssh_try_publickey_from_file(session, keyfile, publickey, type)
    ccall((:ssh_try_publickey_from_file, libssh), Cint, (ssh_session, Ptr{Cchar}, Ptr{ssh_string}, Ptr{Cint}), session, keyfile, publickey, type)
end

function ssh_privatekey_type(privatekey)
    ccall((:ssh_privatekey_type, libssh), ssh_keytypes_e, (ssh_private_key,), privatekey)
end

function ssh_get_pubkey(session)
    ccall((:ssh_get_pubkey, libssh), ssh_string, (ssh_session,), session)
end

function ssh_message_retrieve(session, packettype)
    ccall((:ssh_message_retrieve, libssh), ssh_message, (ssh_session, UInt32), session, packettype)
end

function ssh_message_auth_publickey(msg)
    ccall((:ssh_message_auth_publickey, libssh), ssh_public_key, (ssh_message,), msg)
end

function string_burn(str)
    ccall((:string_burn, libssh), Cvoid, (ssh_string,), str)
end

function string_copy(str)
    ccall((:string_copy, libssh), ssh_string, (ssh_string,), str)
end

function string_data(str)
    ccall((:string_data, libssh), Ptr{Cvoid}, (ssh_string,), str)
end

function string_fill(str, data, len)
    ccall((:string_fill, libssh), Cint, (ssh_string, Ptr{Cvoid}, Csize_t), str, data, len)
end

function string_free(str)
    ccall((:string_free, libssh), Cvoid, (ssh_string,), str)
end

function string_from_char(what)
    ccall((:string_from_char, libssh), ssh_string, (Ptr{Cchar},), what)
end

function string_len(str)
    ccall((:string_len, libssh), Csize_t, (ssh_string,), str)
end

function string_new(size)
    ccall((:string_new, libssh), ssh_string, (Csize_t,), size)
end

function string_to_char(str)
    ccall((:string_to_char, libssh), Ptr{Cchar}, (ssh_string,), str)
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

Base.unsafe_convert(::Type{Ptr{__JL_sftp_request_queue_struct}}, x::Ref) = Base.unsafe_convert(Ptr{__JL_sftp_request_queue_struct}, Base.unsafe_convert(Ptr{sftp_request_queue_struct}, x))

Base.unsafe_convert(::Type{Ptr{__JL_sftp_request_queue_struct}}, x::Ptr) = Ptr{__JL_sftp_request_queue_struct}(x)

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

Base.unsafe_convert(::Type{Ptr{__JL_sftp_packet_struct}}, x::Ref) = Base.unsafe_convert(Ptr{__JL_sftp_packet_struct}, Base.unsafe_convert(Ptr{sftp_packet_struct}, x))

Base.unsafe_convert(::Type{Ptr{__JL_sftp_packet_struct}}, x::Ptr) = Ptr{__JL_sftp_packet_struct}(x)

const sftp_packet = Ptr{__JL_sftp_packet_struct}

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
end

const sftp_session = Ptr{sftp_session_struct}

struct sftp_client_message_struct
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

struct sftp_dir_struct
    sftp::sftp_session
    name::Ptr{Cchar}
    handle::ssh_string
    buffer::ssh_buffer
    count::UInt32
    eof::Cint
end

const sftp_dir = Ptr{sftp_dir_struct}

struct sftp_file_struct
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

struct sftp_status_message_struct
    id::UInt32
    status::UInt32
    error_unused::ssh_string
    lang_unused::ssh_string
    errormsg::Ptr{Cchar}
    langmsg::Ptr{Cchar}
end

const sftp_status_message = Ptr{sftp_status_message_struct}

struct sftp_statvfs_struct
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

struct sftp_packet_struct
    sftp::sftp_session
    type::UInt8
    payload::ssh_buffer
end

struct sftp_request_queue_struct
    next::sftp_request_queue
    message::sftp_message
end

function sftp_new(session)
    ccall((:sftp_new, libssh), sftp_session, (ssh_session,), session)
end

function sftp_new_channel(session, channel)
    ccall((:sftp_new_channel, libssh), sftp_session, (ssh_session, ssh_channel), session, channel)
end

function sftp_free(sftp)
    ccall((:sftp_free, libssh), Cvoid, (sftp_session,), sftp)
end

function sftp_init(sftp)
    ccall((:sftp_init, libssh), Cint, (sftp_session,), sftp)
end

function sftp_get_error(sftp)
    ccall((:sftp_get_error, libssh), Cint, (sftp_session,), sftp)
end

function sftp_extensions_get_count(sftp)
    ccall((:sftp_extensions_get_count, libssh), Cuint, (sftp_session,), sftp)
end

function sftp_extensions_get_name(sftp, indexn)
    ccall((:sftp_extensions_get_name, libssh), Ptr{Cchar}, (sftp_session, Cuint), sftp, indexn)
end

function sftp_extensions_get_data(sftp, indexn)
    ccall((:sftp_extensions_get_data, libssh), Ptr{Cchar}, (sftp_session, Cuint), sftp, indexn)
end

function sftp_extension_supported(sftp, name, data)
    ccall((:sftp_extension_supported, libssh), Cint, (sftp_session, Ptr{Cchar}, Ptr{Cchar}), sftp, name, data)
end

function sftp_opendir(session, path)
    ccall((:sftp_opendir, libssh), sftp_dir, (sftp_session, Ptr{Cchar}), session, path)
end

function sftp_readdir(session, dir)
    ccall((:sftp_readdir, libssh), sftp_attributes, (sftp_session, sftp_dir), session, dir)
end

function sftp_dir_eof(dir)
    ccall((:sftp_dir_eof, libssh), Cint, (sftp_dir,), dir)
end

function sftp_stat(session, path)
    ccall((:sftp_stat, libssh), sftp_attributes, (sftp_session, Ptr{Cchar}), session, path)
end

function sftp_lstat(session, path)
    ccall((:sftp_lstat, libssh), sftp_attributes, (sftp_session, Ptr{Cchar}), session, path)
end

function sftp_fstat(file)
    ccall((:sftp_fstat, libssh), sftp_attributes, (sftp_file,), file)
end

function sftp_attributes_free(file)
    ccall((:sftp_attributes_free, libssh), Cvoid, (sftp_attributes,), file)
end

function sftp_closedir(dir)
    ccall((:sftp_closedir, libssh), Cint, (sftp_dir,), dir)
end

function sftp_close(file)
    ccall((:sftp_close, libssh), Cint, (sftp_file,), file)
end

function sftp_open(session, file, accesstype, mode)
    ccall((:sftp_open, libssh), sftp_file, (sftp_session, Ptr{Cchar}, Cint, mode_t), session, file, accesstype, mode)
end

function sftp_file_set_nonblocking(handle)
    ccall((:sftp_file_set_nonblocking, libssh), Cvoid, (sftp_file,), handle)
end

function sftp_file_set_blocking(handle)
    ccall((:sftp_file_set_blocking, libssh), Cvoid, (sftp_file,), handle)
end

function sftp_read(file, buf, count)
    ccall((:sftp_read, libssh), Cssize_t, (sftp_file, Ptr{Cvoid}, Csize_t), file, buf, count)
end

function sftp_async_read_begin(file, len)
    ccall((:sftp_async_read_begin, libssh), Cint, (sftp_file, UInt32), file, len)
end

function sftp_async_read(file, data, len, id)
    ccall((:sftp_async_read, libssh), Cint, (sftp_file, Ptr{Cvoid}, UInt32, UInt32), file, data, len, id)
end

function sftp_write(file, buf, count)
    ccall((:sftp_write, libssh), Cssize_t, (sftp_file, Ptr{Cvoid}, Csize_t), file, buf, count)
end

function sftp_seek(file, new_offset)
    ccall((:sftp_seek, libssh), Cint, (sftp_file, UInt32), file, new_offset)
end

function sftp_seek64(file, new_offset)
    ccall((:sftp_seek64, libssh), Cint, (sftp_file, UInt64), file, new_offset)
end

function sftp_tell(file)
    ccall((:sftp_tell, libssh), Culong, (sftp_file,), file)
end

function sftp_tell64(file)
    ccall((:sftp_tell64, libssh), UInt64, (sftp_file,), file)
end

function sftp_rewind(file)
    ccall((:sftp_rewind, libssh), Cvoid, (sftp_file,), file)
end

function sftp_unlink(sftp, file)
    ccall((:sftp_unlink, libssh), Cint, (sftp_session, Ptr{Cchar}), sftp, file)
end

function sftp_rmdir(sftp, directory)
    ccall((:sftp_rmdir, libssh), Cint, (sftp_session, Ptr{Cchar}), sftp, directory)
end

function sftp_mkdir(sftp, directory, mode)
    ccall((:sftp_mkdir, libssh), Cint, (sftp_session, Ptr{Cchar}, mode_t), sftp, directory, mode)
end

function sftp_rename(sftp, original, newname)
    ccall((:sftp_rename, libssh), Cint, (sftp_session, Ptr{Cchar}, Ptr{Cchar}), sftp, original, newname)
end

function sftp_setstat(sftp, file, attr)
    ccall((:sftp_setstat, libssh), Cint, (sftp_session, Ptr{Cchar}, sftp_attributes), sftp, file, attr)
end

function sftp_chown(sftp, file, owner, group)
    ccall((:sftp_chown, libssh), Cint, (sftp_session, Ptr{Cchar}, uid_t, gid_t), sftp, file, owner, group)
end

function sftp_chmod(sftp, file, mode)
    ccall((:sftp_chmod, libssh), Cint, (sftp_session, Ptr{Cchar}, mode_t), sftp, file, mode)
end

function sftp_utimes(sftp, file, times)
    ccall((:sftp_utimes, libssh), Cint, (sftp_session, Ptr{Cchar}, Ptr{Cvoid}), sftp, file, times)
end

function sftp_symlink(sftp, target, dest)
    ccall((:sftp_symlink, libssh), Cint, (sftp_session, Ptr{Cchar}, Ptr{Cchar}), sftp, target, dest)
end

function sftp_readlink(sftp, path)
    ccall((:sftp_readlink, libssh), Ptr{Cchar}, (sftp_session, Ptr{Cchar}), sftp, path)
end

function sftp_statvfs(sftp, path)
    ccall((:sftp_statvfs, libssh), sftp_statvfs_t, (sftp_session, Ptr{Cchar}), sftp, path)
end

function sftp_fstatvfs(file)
    ccall((:sftp_fstatvfs, libssh), sftp_statvfs_t, (sftp_file,), file)
end

function sftp_statvfs_free(statvfs_o)
    ccall((:sftp_statvfs_free, libssh), Cvoid, (sftp_statvfs_t,), statvfs_o)
end

function sftp_fsync(file)
    ccall((:sftp_fsync, libssh), Cint, (sftp_file,), file)
end

function sftp_canonicalize_path(sftp, path)
    ccall((:sftp_canonicalize_path, libssh), Ptr{Cchar}, (sftp_session, Ptr{Cchar}), sftp, path)
end

function sftp_server_version(sftp)
    ccall((:sftp_server_version, libssh), Cint, (sftp_session,), sftp)
end

function sftp_get_client_message(sftp)
    ccall((:sftp_get_client_message, libssh), sftp_client_message, (sftp_session,), sftp)
end

function sftp_client_message_free(msg)
    ccall((:sftp_client_message_free, libssh), Cvoid, (sftp_client_message,), msg)
end

function sftp_client_message_get_type(msg)
    ccall((:sftp_client_message_get_type, libssh), UInt8, (sftp_client_message,), msg)
end

function sftp_client_message_get_filename(msg)
    ccall((:sftp_client_message_get_filename, libssh), Ptr{Cchar}, (sftp_client_message,), msg)
end

function sftp_client_message_set_filename(msg, newname)
    ccall((:sftp_client_message_set_filename, libssh), Cvoid, (sftp_client_message, Ptr{Cchar}), msg, newname)
end

function sftp_client_message_get_data(msg)
    ccall((:sftp_client_message_get_data, libssh), Ptr{Cchar}, (sftp_client_message,), msg)
end

function sftp_client_message_get_flags(msg)
    ccall((:sftp_client_message_get_flags, libssh), UInt32, (sftp_client_message,), msg)
end

function sftp_client_message_get_submessage(msg)
    ccall((:sftp_client_message_get_submessage, libssh), Ptr{Cchar}, (sftp_client_message,), msg)
end

function sftp_send_client_message(sftp, msg)
    ccall((:sftp_send_client_message, libssh), Cint, (sftp_session, sftp_client_message), sftp, msg)
end

function sftp_reply_name(msg, name, attr)
    ccall((:sftp_reply_name, libssh), Cint, (sftp_client_message, Ptr{Cchar}, sftp_attributes), msg, name, attr)
end

function sftp_reply_handle(msg, handle)
    ccall((:sftp_reply_handle, libssh), Cint, (sftp_client_message, ssh_string), msg, handle)
end

function sftp_handle_alloc(sftp, info)
    ccall((:sftp_handle_alloc, libssh), ssh_string, (sftp_session, Ptr{Cvoid}), sftp, info)
end

function sftp_reply_attr(msg, attr)
    ccall((:sftp_reply_attr, libssh), Cint, (sftp_client_message, sftp_attributes), msg, attr)
end

function sftp_handle(sftp, handle)
    ccall((:sftp_handle, libssh), Ptr{Cvoid}, (sftp_session, ssh_string), sftp, handle)
end

function sftp_reply_status(msg, status, message)
    ccall((:sftp_reply_status, libssh), Cint, (sftp_client_message, UInt32, Ptr{Cchar}), msg, status, message)
end

function sftp_reply_names_add(msg, file, longname, attr)
    ccall((:sftp_reply_names_add, libssh), Cint, (sftp_client_message, Ptr{Cchar}, Ptr{Cchar}, sftp_attributes), msg, file, longname, attr)
end

function sftp_reply_names(msg)
    ccall((:sftp_reply_names, libssh), Cint, (sftp_client_message,), msg)
end

function sftp_reply_data(msg, data, len)
    ccall((:sftp_reply_data, libssh), Cint, (sftp_client_message, Ptr{Cvoid}, Cint), msg, data, len)
end

function sftp_handle_remove(sftp, handle)
    ccall((:sftp_handle_remove, libssh), Cvoid, (sftp_session, Ptr{Cvoid}), sftp, handle)
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
end

mutable struct ssh_bind_struct end

const ssh_bind = Ptr{ssh_bind_struct}

# typedef void ( * ssh_bind_incoming_connection_callback ) ( ssh_bind sshbind , void * userdata )
const ssh_bind_incoming_connection_callback = Ptr{Cvoid}

struct ssh_bind_callbacks_struct
    size::Csize_t
    incoming_connection::ssh_bind_incoming_connection_callback
end

const ssh_bind_callbacks = Ptr{ssh_bind_callbacks_struct}

function ssh_bind_new()
    ccall((:ssh_bind_new, libssh), ssh_bind, ())
end

function ssh_bind_options_set(sshbind, type, value)
    ccall((:ssh_bind_options_set, libssh), Cint, (ssh_bind, ssh_bind_options_e, Ptr{Cvoid}), sshbind, type, value)
end

function ssh_bind_options_parse_config(sshbind, filename)
    ccall((:ssh_bind_options_parse_config, libssh), Cint, (ssh_bind, Ptr{Cchar}), sshbind, filename)
end

function ssh_bind_listen(ssh_bind_o)
    ccall((:ssh_bind_listen, libssh), Cint, (ssh_bind,), ssh_bind_o)
end

function ssh_bind_set_callbacks(sshbind, callbacks, userdata)
    ccall((:ssh_bind_set_callbacks, libssh), Cint, (ssh_bind, ssh_bind_callbacks, Ptr{Cvoid}), sshbind, callbacks, userdata)
end

function ssh_bind_set_blocking(ssh_bind_o, blocking)
    ccall((:ssh_bind_set_blocking, libssh), Cvoid, (ssh_bind, Cint), ssh_bind_o, blocking)
end

function ssh_bind_get_fd(ssh_bind_o)
    ccall((:ssh_bind_get_fd, libssh), socket_t, (ssh_bind,), ssh_bind_o)
end

function ssh_bind_set_fd(ssh_bind_o, fd)
    ccall((:ssh_bind_set_fd, libssh), Cvoid, (ssh_bind, socket_t), ssh_bind_o, fd)
end

function ssh_bind_fd_toaccept(ssh_bind_o)
    ccall((:ssh_bind_fd_toaccept, libssh), Cvoid, (ssh_bind,), ssh_bind_o)
end

function ssh_bind_accept(ssh_bind_o, session)
    ccall((:ssh_bind_accept, libssh), Cint, (ssh_bind, ssh_session), ssh_bind_o, session)
end

function ssh_bind_accept_fd(ssh_bind_o, session, fd)
    ccall((:ssh_bind_accept_fd, libssh), Cint, (ssh_bind, ssh_session, socket_t), ssh_bind_o, session, fd)
end

function ssh_gssapi_get_creds(session)
    ccall((:ssh_gssapi_get_creds, libssh), ssh_gssapi_creds, (ssh_session,), session)
end

function ssh_handle_key_exchange(session)
    ccall((:ssh_handle_key_exchange, libssh), Cint, (ssh_session,), session)
end

function ssh_server_init_kex(session)
    ccall((:ssh_server_init_kex, libssh), Cint, (ssh_session,), session)
end

function ssh_bind_free(ssh_bind_o)
    ccall((:ssh_bind_free, libssh), Cvoid, (ssh_bind,), ssh_bind_o)
end

function ssh_set_auth_methods(session, auth_methods)
    ccall((:ssh_set_auth_methods, libssh), Cvoid, (ssh_session, Cint), session, auth_methods)
end

function ssh_send_issue_banner(session, banner)
    ccall((:ssh_send_issue_banner, libssh), Cint, (ssh_session, ssh_string), session, banner)
end

function ssh_message_reply_default(msg)
    ccall((:ssh_message_reply_default, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_auth_user(msg)
    ccall((:ssh_message_auth_user, libssh), Ptr{Cchar}, (ssh_message,), msg)
end

function ssh_message_auth_password(msg)
    ccall((:ssh_message_auth_password, libssh), Ptr{Cchar}, (ssh_message,), msg)
end

function ssh_message_auth_pubkey(msg)
    ccall((:ssh_message_auth_pubkey, libssh), ssh_key, (ssh_message,), msg)
end

function ssh_message_auth_kbdint_is_response(msg)
    ccall((:ssh_message_auth_kbdint_is_response, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_auth_publickey_state(msg)
    ccall((:ssh_message_auth_publickey_state, libssh), ssh_publickey_state_e, (ssh_message,), msg)
end

function ssh_message_auth_reply_success(msg, partial)
    ccall((:ssh_message_auth_reply_success, libssh), Cint, (ssh_message, Cint), msg, partial)
end

function ssh_message_auth_reply_pk_ok(msg, algo, pubkey)
    ccall((:ssh_message_auth_reply_pk_ok, libssh), Cint, (ssh_message, ssh_string, ssh_string), msg, algo, pubkey)
end

function ssh_message_auth_reply_pk_ok_simple(msg)
    ccall((:ssh_message_auth_reply_pk_ok_simple, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_auth_set_methods(msg, methods)
    ccall((:ssh_message_auth_set_methods, libssh), Cint, (ssh_message, Cint), msg, methods)
end

function ssh_message_auth_interactive_request(msg, name, instruction, num_prompts, prompts, echo)
    ccall((:ssh_message_auth_interactive_request, libssh), Cint, (ssh_message, Ptr{Cchar}, Ptr{Cchar}, Cuint, Ptr{Ptr{Cchar}}, Ptr{Cchar}), msg, name, instruction, num_prompts, prompts, echo)
end

function ssh_message_service_reply_success(msg)
    ccall((:ssh_message_service_reply_success, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_service_service(msg)
    ccall((:ssh_message_service_service, libssh), Ptr{Cchar}, (ssh_message,), msg)
end

function ssh_message_global_request_reply_success(msg, bound_port)
    ccall((:ssh_message_global_request_reply_success, libssh), Cint, (ssh_message, UInt16), msg, bound_port)
end

function ssh_set_message_callback(session, ssh_bind_message_callback, data)
    ccall((:ssh_set_message_callback, libssh), Cvoid, (ssh_session, Ptr{Cvoid}, Ptr{Cvoid}), session, ssh_bind_message_callback, data)
end

function ssh_execute_message_callbacks(session)
    ccall((:ssh_execute_message_callbacks, libssh), Cint, (ssh_session,), session)
end

function ssh_message_channel_request_open_originator(msg)
    ccall((:ssh_message_channel_request_open_originator, libssh), Ptr{Cchar}, (ssh_message,), msg)
end

function ssh_message_channel_request_open_originator_port(msg)
    ccall((:ssh_message_channel_request_open_originator_port, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_channel_request_open_destination(msg)
    ccall((:ssh_message_channel_request_open_destination, libssh), Ptr{Cchar}, (ssh_message,), msg)
end

function ssh_message_channel_request_open_destination_port(msg)
    ccall((:ssh_message_channel_request_open_destination_port, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_channel_request_channel(msg)
    ccall((:ssh_message_channel_request_channel, libssh), ssh_channel, (ssh_message,), msg)
end

function ssh_message_channel_request_pty_term(msg)
    ccall((:ssh_message_channel_request_pty_term, libssh), Ptr{Cchar}, (ssh_message,), msg)
end

function ssh_message_channel_request_pty_width(msg)
    ccall((:ssh_message_channel_request_pty_width, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_channel_request_pty_height(msg)
    ccall((:ssh_message_channel_request_pty_height, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_channel_request_pty_pxwidth(msg)
    ccall((:ssh_message_channel_request_pty_pxwidth, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_channel_request_pty_pxheight(msg)
    ccall((:ssh_message_channel_request_pty_pxheight, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_channel_request_env_name(msg)
    ccall((:ssh_message_channel_request_env_name, libssh), Ptr{Cchar}, (ssh_message,), msg)
end

function ssh_message_channel_request_env_value(msg)
    ccall((:ssh_message_channel_request_env_value, libssh), Ptr{Cchar}, (ssh_message,), msg)
end

function ssh_message_channel_request_command(msg)
    ccall((:ssh_message_channel_request_command, libssh), Ptr{Cchar}, (ssh_message,), msg)
end

function ssh_message_channel_request_subsystem(msg)
    ccall((:ssh_message_channel_request_subsystem, libssh), Ptr{Cchar}, (ssh_message,), msg)
end

function ssh_message_channel_request_x11_single_connection(msg)
    ccall((:ssh_message_channel_request_x11_single_connection, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_channel_request_x11_auth_protocol(msg)
    ccall((:ssh_message_channel_request_x11_auth_protocol, libssh), Ptr{Cchar}, (ssh_message,), msg)
end

function ssh_message_channel_request_x11_auth_cookie(msg)
    ccall((:ssh_message_channel_request_x11_auth_cookie, libssh), Ptr{Cchar}, (ssh_message,), msg)
end

function ssh_message_channel_request_x11_screen_number(msg)
    ccall((:ssh_message_channel_request_x11_screen_number, libssh), Cint, (ssh_message,), msg)
end

function ssh_message_global_request_address(msg)
    ccall((:ssh_message_global_request_address, libssh), Ptr{Cchar}, (ssh_message,), msg)
end

function ssh_message_global_request_port(msg)
    ccall((:ssh_message_global_request_port, libssh), Cint, (ssh_message,), msg)
end

function ssh_channel_open_reverse_forward(channel, remotehost, remoteport, sourcehost, localport)
    ccall((:ssh_channel_open_reverse_forward, libssh), Cint, (ssh_channel, Ptr{Cchar}, Cint, Ptr{Cchar}, Cint), channel, remotehost, remoteport, sourcehost, localport)
end

function ssh_channel_request_send_exit_status(channel, exit_status)
    ccall((:ssh_channel_request_send_exit_status, libssh), Cint, (ssh_channel, Cint), channel, exit_status)
end

function ssh_channel_request_send_exit_signal(channel, signum, core, errmsg, lang)
    ccall((:ssh_channel_request_send_exit_signal, libssh), Cint, (ssh_channel, Ptr{Cchar}, Cint, Ptr{Cchar}, Ptr{Cchar}), channel, signum, core, errmsg, lang)
end

function ssh_send_keepalive(session)
    ccall((:ssh_send_keepalive, libssh), Cint, (ssh_session,), session)
end

function ssh_accept(session)
    ccall((:ssh_accept, libssh), Cint, (ssh_session,), session)
end

function channel_write_stderr(channel, data, len)
    ccall((:channel_write_stderr, libssh), Cint, (ssh_channel, Ptr{Cvoid}, UInt32), channel, data, len)
end

# typedef void ( * ssh_callback_int ) ( int code , void * user )
const ssh_callback_int = Ptr{Cvoid}

# typedef size_t ( * ssh_callback_data ) ( const void * data , size_t len , void * user )
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
const ssh_log_callback = Ptr{Cvoid}

# typedef void ( * ssh_logging_callback ) ( int priority , const char * function , const char * buffer , void * userdata )
const ssh_logging_callback = Ptr{Cvoid}

# typedef void ( * ssh_status_callback ) ( ssh_session session , float status , void * userdata )
const ssh_status_callback = Ptr{Cvoid}

# typedef void ( * ssh_global_request_callback ) ( ssh_session session , ssh_message message , void * userdata )
const ssh_global_request_callback = Ptr{Cvoid}

# typedef ssh_channel ( * ssh_channel_open_request_x11_callback ) ( ssh_session session , const char * originator_address , int originator_port , void * userdata )
const ssh_channel_open_request_x11_callback = Ptr{Cvoid}

# typedef ssh_channel ( * ssh_channel_open_request_auth_agent_callback ) ( ssh_session session , void * userdata )
const ssh_channel_open_request_auth_agent_callback = Ptr{Cvoid}

struct ssh_callbacks_struct
    size::Csize_t
    userdata::Ptr{Cvoid}
    auth_function::ssh_auth_callback
    log_function::ssh_log_callback
    connect_status_function::Ptr{Cvoid}
    global_request_function::ssh_global_request_callback
    channel_open_request_x11_function::ssh_channel_open_request_x11_callback
    channel_open_request_auth_agent_function::ssh_channel_open_request_auth_agent_callback
end

const ssh_callbacks = Ptr{ssh_callbacks_struct}

# typedef int ( * ssh_auth_password_callback ) ( ssh_session session , const char * user , const char * password , void * userdata )
const ssh_auth_password_callback = Ptr{Cvoid}

# typedef int ( * ssh_auth_none_callback ) ( ssh_session session , const char * user , void * userdata )
const ssh_auth_none_callback = Ptr{Cvoid}

# typedef int ( * ssh_auth_gssapi_mic_callback ) ( ssh_session session , const char * user , const char * principal , void * userdata )
const ssh_auth_gssapi_mic_callback = Ptr{Cvoid}

# typedef int ( * ssh_auth_pubkey_callback ) ( ssh_session session , const char * user , struct ssh_key_struct * pubkey , char signature_state , void * userdata )
const ssh_auth_pubkey_callback = Ptr{Cvoid}

# typedef int ( * ssh_service_request_callback ) ( ssh_session session , const char * service , void * userdata )
const ssh_service_request_callback = Ptr{Cvoid}

# typedef ssh_channel ( * ssh_channel_open_request_session_callback ) ( ssh_session session , void * userdata )
const ssh_channel_open_request_session_callback = Ptr{Cvoid}

# typedef ssh_string ( * ssh_gssapi_select_oid_callback ) ( ssh_session session , const char * user , int n_oid , ssh_string * oids , void * userdata )
const ssh_gssapi_select_oid_callback = Ptr{Cvoid}

# typedef int ( * ssh_gssapi_accept_sec_ctx_callback ) ( ssh_session session , ssh_string input_token , ssh_string * output_token , void * userdata )
const ssh_gssapi_accept_sec_ctx_callback = Ptr{Cvoid}

# typedef int ( * ssh_gssapi_verify_mic_callback ) ( ssh_session session , ssh_string mic , void * mic_buffer , size_t mic_buffer_size , void * userdata )
const ssh_gssapi_verify_mic_callback = Ptr{Cvoid}

struct ssh_server_callbacks_struct
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

const ssh_server_callbacks = Ptr{ssh_server_callbacks_struct}

function ssh_set_server_callbacks(session, cb)
    ccall((:ssh_set_server_callbacks, libssh), Cint, (ssh_session, ssh_server_callbacks), session, cb)
end

struct ssh_socket_callbacks_struct
    userdata::Ptr{Cvoid}
    data::ssh_callback_data
    controlflow::ssh_callback_int
    exception::ssh_callback_int_int
    connected::ssh_callback_int_int
end

const ssh_socket_callbacks = Ptr{ssh_socket_callbacks_struct}

# typedef int ( * ssh_packet_callback ) ( ssh_session session , uint8_t type , ssh_buffer packet , void * user )
const ssh_packet_callback = Ptr{Cvoid}

struct ssh_packet_callbacks_struct
    start::UInt8
    n_callbacks::UInt8
    callbacks::Ptr{ssh_packet_callback}
    user::Ptr{Cvoid}
end

const ssh_packet_callbacks = Ptr{ssh_packet_callbacks_struct}

function ssh_set_callbacks(session, cb)
    ccall((:ssh_set_callbacks, libssh), Cint, (ssh_session, ssh_callbacks), session, cb)
end

# typedef int ( * ssh_channel_data_callback ) ( ssh_session session , ssh_channel channel , void * data , uint32_t len , int is_stderr , void * userdata )
const ssh_channel_data_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_eof_callback ) ( ssh_session session , ssh_channel channel , void * userdata )
const ssh_channel_eof_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_close_callback ) ( ssh_session session , ssh_channel channel , void * userdata )
const ssh_channel_close_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_signal_callback ) ( ssh_session session , ssh_channel channel , const char * signal , void * userdata )
const ssh_channel_signal_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_exit_status_callback ) ( ssh_session session , ssh_channel channel , int exit_status , void * userdata )
const ssh_channel_exit_status_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_exit_signal_callback ) ( ssh_session session , ssh_channel channel , const char * signal , int core , const char * errmsg , const char * lang , void * userdata )
const ssh_channel_exit_signal_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_pty_request_callback ) ( ssh_session session , ssh_channel channel , const char * term , int width , int height , int pxwidth , int pwheight , void * userdata )
const ssh_channel_pty_request_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_shell_request_callback ) ( ssh_session session , ssh_channel channel , void * userdata )
const ssh_channel_shell_request_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_auth_agent_req_callback ) ( ssh_session session , ssh_channel channel , void * userdata )
const ssh_channel_auth_agent_req_callback = Ptr{Cvoid}

# typedef void ( * ssh_channel_x11_req_callback ) ( ssh_session session , ssh_channel channel , int single_connection , const char * auth_protocol , const char * auth_cookie , uint32_t screen_number , void * userdata )
const ssh_channel_x11_req_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_pty_window_change_callback ) ( ssh_session session , ssh_channel channel , int width , int height , int pxwidth , int pwheight , void * userdata )
const ssh_channel_pty_window_change_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_exec_request_callback ) ( ssh_session session , ssh_channel channel , const char * command , void * userdata )
const ssh_channel_exec_request_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_env_request_callback ) ( ssh_session session , ssh_channel channel , const char * env_name , const char * env_value , void * userdata )
const ssh_channel_env_request_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_subsystem_request_callback ) ( ssh_session session , ssh_channel channel , const char * subsystem , void * userdata )
const ssh_channel_subsystem_request_callback = Ptr{Cvoid}

# typedef int ( * ssh_channel_write_wontblock_callback ) ( ssh_session session , ssh_channel channel , uint32_t bytes , void * userdata )
const ssh_channel_write_wontblock_callback = Ptr{Cvoid}

struct ssh_channel_callbacks_struct
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
end

const ssh_channel_callbacks = Ptr{ssh_channel_callbacks_struct}

function ssh_set_channel_callbacks(channel, cb)
    ccall((:ssh_set_channel_callbacks, libssh), Cint, (ssh_channel, ssh_channel_callbacks), channel, cb)
end

function ssh_add_channel_callbacks(channel, cb)
    ccall((:ssh_add_channel_callbacks, libssh), Cint, (ssh_channel, ssh_channel_callbacks), channel, cb)
end

function ssh_remove_channel_callbacks(channel, cb)
    ccall((:ssh_remove_channel_callbacks, libssh), Cint, (ssh_channel, ssh_channel_callbacks), channel, cb)
end

# typedef int ( * ssh_thread_callback ) ( void * * lock )
const ssh_thread_callback = Ptr{Cvoid}

# typedef unsigned long ( * ssh_thread_id_callback ) ( void )
const ssh_thread_id_callback = Ptr{Cvoid}

struct ssh_threads_callbacks_struct
    type::Ptr{Cchar}
    mutex_init::ssh_thread_callback
    mutex_destroy::ssh_thread_callback
    mutex_lock::ssh_thread_callback
    mutex_unlock::ssh_thread_callback
    thread_id::ssh_thread_id_callback
end

function ssh_threads_set_callbacks(cb)
    ccall((:ssh_threads_set_callbacks, libssh), Cint, (Ptr{ssh_threads_callbacks_struct},), cb)
end

function ssh_threads_get_default()
    ccall((:ssh_threads_get_default, libssh), Ptr{ssh_threads_callbacks_struct}, ())
end

function ssh_threads_get_pthread()
    ccall((:ssh_threads_get_pthread, libssh), Ptr{ssh_threads_callbacks_struct}, ())
end

function ssh_threads_get_noop()
    ccall((:ssh_threads_get_noop, libssh), Ptr{ssh_threads_callbacks_struct}, ())
end

function ssh_set_log_callback(cb)
    ccall((:ssh_set_log_callback, libssh), Cint, (ssh_logging_callback,), cb)
end

function ssh_get_log_callback()
    ccall((:ssh_get_log_callback, libssh), ssh_logging_callback, ())
end

# Skipping MacroDefinition: LIBSSH_API __attribute__ ( ( visibility ( "default" ) ) )

# Skipping MacroDefinition: SSH_DEPRECATED __attribute__ ( ( deprecated ) )

const SSH_INVALID_SOCKET = socket_t(-1)

const SSH_CRYPT = 2

const SSH_MAC = 3

const SSH_COMP = 4

const SSH_LANG = 5

const SSH_AUTH_METHOD_UNKNOWN = Cuint(0)

const SSH_AUTH_METHOD_NONE = Cuint(1)

const SSH_AUTH_METHOD_PASSWORD = Cuint(2)

const SSH_AUTH_METHOD_PUBLICKEY = Cuint(4)

const SSH_AUTH_METHOD_HOSTBASED = Cuint(8)

const SSH_AUTH_METHOD_INTERACTIVE = Cuint(16)

const SSH_AUTH_METHOD_GSSAPI_MIC = Cuint(32)

const SSH_CLOSED = 1

const SSH_READ_PENDING = 2

const SSH_CLOSED_ERROR = 4

const SSH_WRITE_PENDING = 8

const MD5_DIGEST_LEN = 16

const SSH_ADDRSTRLEN = 46

const SSH_OK = 0

const SSH_ERROR = -1

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

const LIBSSH_VERSION_MINOR = 10

const LIBSSH_VERSION_MICRO = 5

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

const SSH_PACKET_USED = 1

const SSH_PACKET_NOT_USED = 2

@enum AuthMethod begin
    AuthMethod_Unknown = SSH_AUTH_METHOD_UNKNOWN
    AuthMethod_None = SSH_AUTH_METHOD_NONE
    AuthMethod_Password = SSH_AUTH_METHOD_PASSWORD
    AuthMethod_PublicKey = SSH_AUTH_METHOD_PUBLICKEY
    AuthMethod_HostBased = SSH_AUTH_METHOD_HOSTBASED
    AuthMethod_Interactive = SSH_AUTH_METHOD_INTERACTIVE
    AuthMethod_GSSAPI_MIC = SSH_AUTH_METHOD_GSSAPI_MIC
end


# exports
const PREFIXES = ["SSH_LOG_", "SSH_OPTIONS_", "SSH_AUTH_", "AuthMethod"]
for name in names(@__MODULE__; all=true), prefix in PREFIXES
    if startswith(string(name), prefix)
        @eval export $name
    end
end

end # module
