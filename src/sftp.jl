"""
$(TYPEDEF)

Enum for possible SFTP error codes. Note that despite its name, `SftpError_Ok`
does not indicate an error.

- `SftpError_Ok`
- `SftpError_Eof`
- `SftpError_NoSuchFile`
- `SftpError_PermissionDenied`
- `SftpError_GenericFailure`
- `SftpError_BadMessage`
- `SftpError_NoConnection`
- `SftpError_ConnectionLost`
- `SftpError_OpUnsupported`
- `SftpError_InvalidHandle`
- `SftpError_NoSuchPath`
- `SftpError_FileAlreadyExists`
- `SftpError_WriteProtect`
- `SftpError_NoMedia`
"""
@enum SftpError begin
    SftpError_Ok = Int(lib.SSH_FX_OK)
    SftpError_Eof = Int(lib.SSH_FX_EOF)
    SftpError_NoSuchFile = Int(lib.SSH_FX_NO_SUCH_FILE)
    SftpError_PermissionDenied = Int(lib.SSH_FX_PERMISSION_DENIED)
    SftpError_GenericFailure = Int(lib.SSH_FX_FAILURE)
    SftpError_BadMessage = Int(lib.SSH_FX_BAD_MESSAGE)
    SftpError_NoConnection = Int(lib.SSH_FX_NO_CONNECTION)
    SftpError_ConnectionLost = Int(lib.SSH_FX_CONNECTION_LOST)
    SftpError_OpUnsupported = Int(lib.SSH_FX_OP_UNSUPPORTED)
    SftpError_InvalidHandle = Int(lib.SSH_FX_INVALID_HANDLE)
    SftpError_NoSuchPath = Int(lib.SSH_FX_NO_SUCH_PATH)
    SftpError_FileAlreadyExists = Int(lib.SSH_FX_FILE_ALREADY_EXISTS)
    SftpError_WriteProtect = Int(lib.SSH_FX_WRITE_PROTECT)
    SftpError_NoMedia = Int(lib.SSH_FX_NO_MEDIA)
end


## SftpAttributes


"""
$(TYPEDEF)

Attributes of remote file objects. This has the following (read-only) properties:
- `name::String`
- `longname::String`
- `flags::UInt32`
- `type::UInt8`
- `size::UInt64`
- `uid::UInt32`
- `gid::UInt32`
- `owner::String`
- `group::String`
- `permissions::UInt32`
- `atime64::UInt64`
- `atime::UInt32`
- `atime_nseconds::UInt32`
- `createtime::UInt64`
- `createtime_nseconds::UInt32`
- `mtime64::UInt64`
- `mtime::UInt32`
- `mtime_nseconds::UInt32`
- `acl::String`
- `extended_count::UInt32`
- `extended_type::String`
- `extended_data::String`
"""
mutable struct SftpAttributes
    ptr::Union{lib.sftp_attributes, Nothing}

    function SftpAttributes(ptr::lib.sftp_attributes)
        self = new(ptr)
        finalizer(close, self)
    end
end

Base.isassigned(attrs::SftpAttributes) = !isnothing(attrs.ptr)

function Base.close(attrs::SftpAttributes)
    if isassigned(attrs)
        lib.sftp_attributes_free(attrs.ptr)
        attrs.ptr = nothing
    end
end

function _show_attrs(io::IO, attrs::SftpAttributes)
    mode = string(attrs.permissions, base=8, pad=6)
    print(io, SftpAttributes, "(name='$(attrs.name)', size=$(attrs.size) bytes, owner=$(attrs.owner), permissions=0o$(mode))")
end

Base.show(io::IO, attrs::SftpAttributes) = _show_attrs(io, attrs)

function _load_attr(x::Ptr{Ptr{Cchar}})
    x = unsafe_load(x)
    x == C_NULL ? "" : unsafe_string(Ptr{UInt8}(x))
end

function _load_attr(x::Ptr{lib.ssh_string})
    x = unsafe_load(x)
    x == C_NULL ? "" : unsafe_string(Ptr{UInt8}(lib.ssh_string_get_char(x)))
end

_load_attr(x) = unsafe_load(x)

function Base.getproperty(attrs::SftpAttributes, name::Symbol)
    if name in fieldnames(lib.sftp_attributes_struct)
        ptr = getfield(attrs, :ptr)
        _load_attr(getproperty(ptr, name))
    else
        getfield(attrs, name)
    end
end


## SftpSession


"""
$(TYPEDEF)

This represents a SFTP session, through which one can do SFTP operations. It is
only usable while its parent [`Session`](@ref) is still open, and it must be
closed explicitly with [`Base.close(::SftpSession)`](@ref) or it will leak
memory.
"""
mutable struct SftpSession
    ptr::Union{lib.sftp_session, Nothing}
    session::Session
    files::Vector{Any}

    _lock::ReentrantLock

    @doc """
    $(TYPEDSIGNATURES)

    Create a `SftpSession` from an existing [`Session`](@ref).

    # Throws
    - `ArgumentError`: If `session` isn't open.
    - [`LibSSHException`](@ref): If creating the SFTP session fails.
    """
    function SftpSession(session::Session)
        if !isopen(session)
            throw(ArgumentError("Session is closed, cannot create an SftpSession with it"))
        end

        ptr = @lockandblock session lib.sftp_new(session.ptr)
        if ptr == C_NULL
            error_msg = get_error(session)
            throw(LibSSHException("Couldn't create an SFTP session, call to lib.sftp_new() failed: '$(error_msg)'"))
        end

        self = new(ptr, session, [], ReentrantLock())

        ret = @lockandblock session lib.sftp_init(ptr)
        if ret != SSH_OK
            error_code = get_error(self)
            close(self)
            throw(LibSSHException("Couldn't initialize the SFTP session, call to lib.sftp_init() failed with $(ret): $(error_code)"))
        end

        push!(session.closeables, self)

        finalizer(_finalizer, self)
    end
end

function _finalizer(sftp::SftpSession)
    if isopen(sftp)
        Threads.@spawn @error "$(sftp) has not been closed, this is a memory leak!"
    end
end

"""
$(TYPEDSIGNATURES)

Do-constructor, the function `f` will be called like `f(sftp)` with the new
[`SftpSession`](@ref).
"""
function SftpSession(f::Function, args...; kwargs...)
    sftp = SftpSession(args...; kwargs...)
    try
        f(sftp)
    finally
        close(sftp)
    end
end

function Base.show(io::IO, sftp::SftpSession)
    if isopen(sftp)
        print(io, SftpSession, "(session=$(sftp.session))")
    else
        print(io, SftpSession, "([closed])")
    end
end

"""
$(TYPEDSIGNATURES)

Lock an [`SftpSession`](@ref).
"""
Base.lock(sftp::SftpSession) = lock(sftp._lock)

"""
$(TYPEDSIGNATURES)

Unlock an [`SftpSession`](@ref).
"""
Base.unlock(sftp::SftpSession) = unlock(sftp._lock)

Base.isassigned(sftp::SftpSession) = !isnothing(sftp.ptr)

"""
$(TYPEDSIGNATURES)

Check if `sftp` is open.
"""
Base.isopen(sftp::SftpSession) = isassigned(sftp)

function Base.unsafe_convert(::Type{lib.sftp_session}, sftp::SftpSession)
    if !isassigned(sftp)
        throw(ArgumentError("The SftpSession doesn't have a valid pointer, cannot convert it to a lib.sftp_session"))
    end

    return sftp.ptr
end

"""
$(TYPEDSIGNATURES)

Close an `SftpSession`. This will also close any open files.
"""
function Base.close(sftp::SftpSession)
    if isassigned(sftp)
        # Close all open files
        for i in reverse(eachindex(sftp.files))
            close(sftp.files[i])
        end

        # Remove from the parent session
        @lock sftp.session begin
            idx = findfirst(x -> x === sftp, sftp.session.closeables)
            if !isnothing(idx)
                popat!(sftp.session.closeables, idx)
            else
                Threads.@spawn @error "Couldn't find $(sftp) in the parent Session, this may be a memory leak."
            end
        end

        lib.sftp_free(sftp.ptr)
        sftp.ptr = nothing
    end
end

"""
$(TYPEDSIGNATURES)

Get the current error code for `sftp`.

# Throws
- `ArgumentError`: If `sftp` is closed.
"""
function get_error(sftp::SftpSession)
    if !isassigned(sftp)
        throw(ArgumentError("The SftpSession doesn't have a valid pointer, cannot get its error message"))
    end

    SftpError(lib.sftp_get_error(sftp))
end

"""
$(TYPEDSIGNATURES)

Get a list of supported server extensions and their versions.

# Throws
- `ArgumentError`: If `sftp` is closed.
"""
function get_extensions(sftp::SftpSession)
    if !isassigned(sftp)
        throw(ArgumentError("The SftpSession doesn't have a valid pointer, cannot get its extensions"))
    end

    extensions = Dict{String, String}()
    count = lib.sftp_extensions_get_count(sftp)
    for i in 0:count - 1
        extensions[lib.sftp_extensions_get_name(sftp, i)] = lib.sftp_extensions_get_data(sftp, i)
    end

    return extensions
end

"""
$(TYPEDSIGNATURES)

Get the server limits. The returned object has the following fields:
- `max_packet_length`
- `max_read_length`
- `max_write_length`
- `max_open_handles`

# Throws
- `ArgumentError`: If `sftp` is closed.
- [`SftpException`](@ref): If getting the limits failed.
"""
function get_limits(sftp::SftpSession)
    if !isassigned(sftp)
        throw(ArgumentError("The SftpSession doesn't have a valid pointer, cannot get its limits"))
    end

    ptr = lib.sftp_limits(sftp)
    if ptr == C_NULL
        throw(SftpException("Couldn't get SFTP limits", sftp))
    end

    limits = unsafe_load(ptr)
    lib.sftp_limits_free(ptr)

    return limits
end

# Undocumented for now because it's difficult to test
function Base.homedir(sftp::SftpSession, username=nothing)
    if !isassigned(sftp)
        throw(ArgumentError("The SftpSession doesn't have a valid pointer, cannot get the home directory"))
    end

    if "home-directory" ∉ keys(get_extensions(sftp))
        error("The SSH server doesn't support the 'home-directory' extension, cannot get the home directory")
    end

    ret = C_NULL
    GC.@preserve username begin
        arg = isnothing(username) ? C_NULL : Base.unsafe_convert(Ptr{Cchar}, username)
        ret = @lockandblock sftp.session lib.sftp_home_directory(sftp.ptr, arg)
    end

    if ret == C_NULL
        throw(SftpException("Couldn't get the home directory", sftp))
    end

    path = unsafe_string(Ptr{UInt8}(ret))
    lib.ssh_string_free_char(ret)

    return path
end

"""
$(TYPEDSIGNATURES)

Read the contents of a remote directory. By default this will behave the same as
`Base.readdir()` and return a list of names, but if `only_names=false` it will
return a list of [`SftpAttributes`](@ref). The `join` and `sort` arguments
are the same as in `Base.readdir()` but only apply when `only_names=true`.

# Throws
- `ArgumentError`: If `sftp` is closed.
- [`SftpException`](@ref): If retrieving the directory contents failed.
"""
function Base.readdir(dir::AbstractString, sftp::SftpSession;
                      only_names=true, join::Bool=false, sort::Bool=true)
    if !isopen(sftp)
        throw(ArgumentError("$(sftp) is closed, cannot call readdir() on it"))
    end

    entries = SftpAttributes[]

    # Open directory
    dir_ptr = GC.@preserve dir begin
        cstr = Base.unsafe_convert(Ptr{Cchar}, dir)
        @lockandblock sftp.session lib.sftp_opendir(sftp.ptr, cstr)
    end
    if dir_ptr == C_NULL
        throw(SftpException("Couldn't open path", dir, sftp))
    end

    # Read contents
    while isopen(sftp)
        attr_ptr = @lockandblock sftp.session lib.sftp_readdir(sftp.ptr, dir_ptr)
        if attr_ptr != C_NULL
            attr = SftpAttributes(attr_ptr)

            # Skip the current and parent entries to be compatible with Base.readdir()
            if attr.name != "." && attr.name != ".."
                push!(entries, attr)
            end
        else
            break
        end
    end

    # Close directory
    ret = @lockandblock sftp.session lib.sftp_closedir(dir_ptr)
    if ret == SSH_ERROR
        throw(SftpException("Closing remote directory failed", dir, sftp))
    end

    if only_names
        entry_names = [x.name for x in entries]
        if join
            map!(x -> _joinpath_linux(dir, x), entry_names, entry_names)
        end
        if sort
            sort!(entry_names)
        end

        return entry_names
    else
        return entries
    end
end

function _rmfile(path, sftp, force=false)
    ret = GC.@preserve path begin
        cstr = Base.unsafe_convert(Ptr{Cchar}, path)
        @lockandblock sftp.session lib.sftp_unlink(sftp.ptr, cstr)
    end
    if ret != 0
        session = sftp.session
        throw(SftpException("Couldn't delete file", path, sftp))
    end
end

function _rmdir(path, sftp, recursive)
    contents = readdir(path, sftp; only_names=false)
    if !isempty(contents)
        if recursive
            for attrs in contents
                rm(_joinpath_linux(path, attrs.name), sftp; attrs, recursive)
            end
        else
            session = sftp.session
            throw(Base.IOError("Cannot delete $(session.user)@$(session.host):$(path), directory not empty", Base.UV_ENOTEMPTY))
        end
    end

    ret = GC.@preserve path begin
        cstr = Base.unsafe_convert(Ptr{Cchar}, path)
        @lockandblock sftp.session lib.sftp_rmdir(sftp.ptr, cstr)
    end
    if ret != 0
        throw(SftpException("Couldn't delete directory", path, sftp))
    end
end

"""
$(TYPEDSIGNATURES)

Delete remote file and directories. This has the same behaviour as `Base.rm()`,
and the `recursive` and `force` options mean the same thing.

Internally the function will call [`Base.stat(::String, ::SftpSession)`](@ref)
to determine how to delete `path`, but if you already have the result of that it
can be passed to the `attrs` keyword argument to avoid the extra blocking call.

# Throws
- `ArgumentError`: If `sftp` is closed.
- `Base.IOError`: If `path` is a non-empty directory and `recursive=false`.
- [`SftpException`](@ref) if deletion fails for some reason.
"""
function Base.rm(path::AbstractString, sftp::SftpSession; attrs=nothing, recursive=false, force=false)
    if !isopen(sftp)
        throw(ArgumentError("$(sftp) is closed, cannot use it to rm()"))
    end

    if isnothing(attrs)
        attrs = try
            stat(path, sftp)
        catch ex
            if ex isa SftpException && ex.error_code == SftpError_NoSuchFile && force
                return
            else
                rethrow()
            end
        end
    end

    if isdir(attrs)
        _rmdir(path, sftp, recursive)
    else
        _rmfile(path, sftp, force)
    end

    return nothing
end

"""
$(TYPEDSIGNATURES)

Make a remote directory. This behaves in exactly the same way as
`Base.mkdir()`.

# Throws
- `ArgumentError`: If `sftp` is closed.
- [`SftpException`](@ref): If making the directory fails.
"""
function Base.mkdir(path::AbstractString, sftp::SftpSession; mode=0o777)
    if !isopen(sftp)
        throw(ArgumentError("$(sftp) is closed, cannot use it to mkdir()"))
    end

    ret = GC.@preserve path begin
        cstr = Base.unsafe_convert(Ptr{Cchar}, path)
        @lockandblock sftp.session lib.sftp_mkdir(sftp.ptr, cstr, lib.mode_t(mode))
    end
    if ret != 0
        throw(SftpException("Creating path failed", path, sftp))
    end

    return path
end

"""
$(TYPEDSIGNATURES)

Move `src` to `dst` remotely. Has the same behaviour as `Base.mv()`.

# Throws
- `ArgumentError`: If `sftp` is closed.
- [`SftpException`](@ref): If the operation fails for some reason.
"""
function Base.mv(src::AbstractString, dst::AbstractString, sftp::SftpSession; force=false)
    if !isopen(sftp)
        throw(ArgumentError("$(sftp) is closed, cannot use it to mv()"))
    end

    if force
        attrs = nothing
        try
            attrs = stat(dst, sftp)
        catch ex
            if !(ex isa SftpException && ex.error_code == SftpError_NoSuchFile)
                rethrow()
            end
        end

        if !isnothing(attrs)
            rm(dst, sftp; attrs, recursive=true)
        end
    end

    ret = GC.@preserve src dst begin
        src_ptr = Base.unsafe_convert(Ptr{Cchar}, src)
        dst_ptr = Base.unsafe_convert(Ptr{Cchar}, dst)
        @lockandblock sftp.session lib.sftp_rename(sftp.ptr, src_ptr, dst_ptr)
    end
    if ret != 0
        throw(SftpException("Renaming path to $(dst) failed", src, sftp))
    end

    return dst
end

"""
$(TYPEDSIGNATURES)

Get information about the file object at `path` as a [`SftpAttributes`](@ref).

Note: the [`Demo.DemoServer`](@ref) does not support setting all of these
properties.

# Throws
- `ArgumentError`: If `sftp` is closed.
- [`SftpException`](@ref): If retrieving the file object information failed
  (e.g. if the path doesn't exist).
"""
function Base.stat(path::String, sftp::SftpSession)
    if !isassigned(sftp)
        throw(ArgumentError("$sftp is closed, cannot stat() with it"))
    end

    ptr = GC.@preserve path begin
        cstr = Base.unsafe_convert(Ptr{Cchar}, path)
        @lockandblock sftp.session lib.sftp_stat(sftp.ptr, cstr)
    end

    if ptr == C_NULL
        throw(SftpException("Couldn't stat path", path, sftp))
    end

    SftpAttributes(ptr)
end

_ismode(attrs, type) = (Filesystem.S_IFMT & attrs.permissions) == type
function _is_file_type(func, path, sftp)
    attrs = nothing

    try
        attrs = stat(path, sftp)
    catch ex
        if !(ex isa SftpException
             && ex.error_code in (SftpError_NoSuchFile, SftpError_NoSuchPath))
            rethrow()
        end
    end

    isnothing(attrs) ? false : func(attrs)
end

"$(TYPEDSIGNATURES)"
Base.ispath(path::AbstractString, sftp::SftpSession) = _is_file_type(ispath, path, sftp)
"$(TYPEDSIGNATURES)"
Base.ispath(::SftpAttributes) = true

"$(TYPEDSIGNATURES)"
Base.isdir(path::AbstractString, sftp::SftpSession) = _is_file_type(isdir, path, sftp)
"$(TYPEDSIGNATURES)"
Base.isdir(attrs::SftpAttributes) = _ismode(attrs, Filesystem.S_IFDIR)

"$(TYPEDSIGNATURES)"
Base.isfile(path::AbstractString, sftp::SftpSession) = _is_file_type(isfile, path, sftp)
"$(TYPEDSIGNATURES)"
Base.isfile(attrs::SftpAttributes) = _ismode(attrs, Filesystem.S_IFREG)

"$(TYPEDSIGNATURES)"
Base.issocket(path::AbstractString, sftp::SftpSession) = _is_file_type(issocket, path, sftp)
"$(TYPEDSIGNATURES)"
Base.issocket(attrs::SftpAttributes) = _ismode(attrs, Filesystem.S_IFSOCK)

"$(TYPEDSIGNATURES)"
Base.islink(path::AbstractString, sftp::SftpSession) = _is_file_type(islink, path, sftp)
"$(TYPEDSIGNATURES)"
Base.islink(attrs::SftpAttributes) = _ismode(attrs, Filesystem.S_IFLNK)

"$(TYPEDSIGNATURES)"
Base.isblockdev(path::AbstractString, sftp::SftpSession) = _is_file_type(isblockdev, path, sftp)
"$(TYPEDSIGNATURES)"
Base.isblockdev(attrs::SftpAttributes) = _ismode(attrs, Filesystem.S_IFBLK)

"$(TYPEDSIGNATURES)"
Base.ischardev(path::AbstractString, sftp::SftpSession) = _is_file_type(ischardev, path, sftp)
"$(TYPEDSIGNATURES)"
Base.ischardev(attrs::SftpAttributes) = _ismode(attrs, Filesystem.S_IFCHR)

"$(TYPEDSIGNATURES)"
Base.isfifo(path::AbstractString, sftp::SftpSession) = _is_file_type(isfifo, path, sftp)
"$(TYPEDSIGNATURES)"
Base.isfifo(attrs::SftpAttributes) = _ismode(attrs, Filesystem.S_IFIFO)


## SftpFile


const FlagsType = @NamedTuple{read::Bool, write::Bool, create::Bool,
                              truncate::Bool, append::Bool, exclusive::Bool}

"""
$(TYPEDEF)
$(TYPEDFIELDS)

Represents a remote file. This object _must_ be explicitly closed with
`close()` or it will leak memory. Don't create one of these yourself, use
[`Base.open(::String, ::SftpSession)`](@ref).
"""
mutable struct SftpFile
    ptr::Union{lib.sftp_file, Nothing}
    sftp::SftpSession
    path::String
    fullpath::String
    flags::FlagsType

    function SftpFile(ptr::lib.sftp_file, sftp::SftpSession, path::String, flags)
        session = sftp.session
        lib.sftp_file_set_nonblocking(ptr)
        self = new(ptr, sftp, path, "$(session.user)@$(session.host):$(path)", flags)
        push!(sftp.files, self)

        finalizer(_finalize, self)
    end
end

# We can't close the file in the finalizer because that requires locking the
# session, which could lead to a task switch.
function _finalize(file::SftpFile)
    if isassigned(file)
        Threads.@spawn @error "$file has not been close()'d, this is a memory leak! The finalizer cannot close the file because it can require task switching."
    end
end

function Base.unsafe_convert(::Type{lib.sftp_file}, file::SftpFile)
    if !isopen(file)
        throw(ArgumentError("$file has been closed, cannot convert it to a pointer"))
    end

    file.ptr
end

Base.isassigned(file::SftpFile) = !isnothing(file.ptr)

"""
$(TYPEDSIGNATURES)

Check if `file` is open.
"""
Base.isopen(file::SftpFile) = isassigned(file)

"""
$(TYPEDSIGNATURES)

Check if `file` is open and readable.
"""
Base.isreadable(file::SftpFile) = isopen(file) && file.flags.read

"""
$(TYPEDSIGNATURES)

Check if `file` is open and readonly.
"""
Base.isreadonly(file::SftpFile) = isopen(file) && file.flags.read && !file.flags.write

"""
$(TYPEDSIGNATURES)

Check if `file` is open and writable.
"""
Base.iswritable(file::SftpFile) = isopen(file) && file.flags.write

"""
$(TYPEDSIGNATURES)

Close `file`. This _must_ be called explicitly, and not in a finalizer because
it may cause a task switch.
"""
function Base.close(file::SftpFile)
    if isassigned(file)
        @lock file.sftp begin
            idx = findfirst(x -> x === file, file.sftp.files)
            if !isnothing(idx)
                popat!(file.sftp.files, idx)
            else
                @error "Couldn't find $file in the parent SFTP session, this may be a memory leak."
            end
        end

        @lockandblock file.sftp.session lib.sftp_close(file.ptr)
        file.ptr = nothing
    end
end

function Base.show(io::IO, file::SftpFile)
    state = isopen(file) ? "open" : "closed"
    print(io, SftpFile, "($(file.fullpath) [$(state)])")
end

"""
$(TYPEDSIGNATURES)

Open a remote file. Most of the keyword arguments behave in exactly the same way
as their counterparts in `Base.open(::String)`, except for `exclusive` and
`mode`, which are unique to this method:
- `exclusive`: Open a file with the `O_EXCL` flag.
- `mode`: If `create=true` and the file doesn't exist, it will be created with
  permissions `(mode & ~umask)`.

# Throws
- `ArgumentError`: If `sftp` is closed.
- [`SftpException`](@ref): If opening the file fails.
"""
function Base.open(path::String, sftp::SftpSession;
                   read::Union{Bool, Nothing}=nothing,
                   write::Union{Bool, Nothing}=nothing,
                   create::Union{Bool, Nothing}=nothing,
                   truncate::Union{Bool, Nothing}=nothing,
                   append::Union{Bool, Nothing}=nothing,
                   exclusive::Bool=false,
                   mode::Unsigned=0o644)
    if !isassigned(sftp)
        throw(ArgumentError("$(sftp) has been closed, cannot use it to open a file"))
    end

    flags = Base.open_flags(; read, write, create, truncate, append)
    accesstype = if flags.read && !flags.write
        Filesystem.JL_O_RDONLY
    elseif !flags.read && flags.write
        Filesystem.JL_O_WRONLY
    elseif flags.read && flags.write
        Filesystem.JL_O_RDWR
    end

    if flags.create
        accesstype |= Filesystem.JL_O_CREAT
    end
    if flags.truncate
        accesstype |= Filesystem.JL_O_TRUNC
    end
    if exclusive
        accesstype |= Filesystem.JL_O_EXCL
    end

    ret = C_NULL
    GC.@preserve path begin
        cstr = Base.unsafe_convert(Ptr{Cchar}, path)
        ret = @lockandblock sftp.session lib.sftp_open(sftp.ptr, cstr, Cint(accesstype), lib.mode_t(mode))
    end

    if ret == C_NULL
        throw(SftpException("Couldn't open file", path, sftp))
    end

    file = SftpFile(ret, sftp, path, (; flags..., exclusive))

    if flags.append
        seekend(file)
    end

    return file
end

"""
$(TYPEDSIGNATURES)

Do-constructor for [`SftpFile`](@ref)'s, the function `f` will be called like
`f(file)`.
"""
function Base.open(f::Function, path::String, sftp::SftpSession; kwargs...)
    file = open(path, sftp; kwargs...)

    try
        f(file)
    finally
        close(file)
    end
end

"""
$(TYPEDSIGNATURES)

Get the current position in `file.`

# Throws
- `ArgumentError`: If `file` is closed.
"""
function Base.position(file::SftpFile)
    if !isopen(file)
        throw(ArgumentError("$file is not open, cannot get its position"))
    end

    lib.sftp_tell64(file)
end

"""
$(TYPEDSIGNATURES)

Go to position `pos` in `file`. Note that this will not validate `pos`.

# Throws
- `ArgumentError`: If `file` is closed.
"""
function Base.seek(file::SftpFile, pos::Integer)
    if !isopen(file)
        throw(ArgumentError("$file is not open, cannot seek() it"))
    end

    lib.sftp_seek64(file, pos)
    return nothing
end

"""
$(TYPEDSIGNATURES)

Go to the beginning of `file`.
"""
Base.seekstart(file::SftpFile) = seek(file, 0)

"""
$(TYPEDSIGNATURES)

Go to the end of `file`.
"""
Base.seekend(file::SftpFile) = seek(file, stat(file.path, file.sftp).size)

"""
$(TYPEDSIGNATURES)

Read at most `nb` bytes from the remote [`SftpFile`](@ref). Uses
[`Base.read!(::SftpFile, ::Vector{UInt8})`](@ref) internally.

# Throws
- `ArgumentError`: If `file` is closed.
- [`SftpException`](@ref): If reading failed.
"""
function Base.read(file::SftpFile, nb::Integer=typemax(Int))
    if !isopen(file)
        throw(ArgumentError("$file is closed, cannot read from it"))
    end

    if nb == typemax(Int)
        nb = stat(file.path, file.sftp).size - position(file)
    end

    out = Vector{UInt8}(undef, (nb,))
    read!(file, out)

    return out
end

"""
$(TYPEDSIGNATURES)

Read `length(out)` bytes from the remote [`SftpFile`](@ref) into `out`. This
uses libssh's asynchronous IO functions under the hood so it may launch multiple
parallel requests.

# Throws
- `ArgumentError`: If `file` is closed.
- [`SftpException`](@ref): If reading failed.
"""
function Base.read!(file::SftpFile, out::Vector{UInt8})
    if !isopen(file)
        throw(ArgumentError("$file is closed, cannot read from it"))
    end

    nb = length(out)
    handles = []
    free_handles = () -> map(x -> lib.sftp_aio_free(x[3][]), handles)

    # Launch requests
    bytes_requested = 0
    try
        while bytes_requested < nb
            handle = Ref{lib.sftp_aio}()
            ret = lib.sftp_aio_begin_read(file, nb - bytes_requested, handle)
            if ret == SSH_ERROR
                throw(SftpException("Reading file failed", file))
            end

            push!(handles, (bytes_requested + 1, ret, handle))
            bytes_requested += ret
        end
    catch
        free_handles()
        rethrow()
    end

    # Wait for the requests to be completed
    try
        for (pos, chunk_size, handle) in handles
            GC.@preserve handle out begin
                handle_ptr = Base.unsafe_convert(Ptr{lib.sftp_aio}, handle)
                buffer_ptr = Ptr{Cvoid}(pointer(out, pos))
                ret = _session_trywait(file.sftp.session) do
                    @lockandblock file.sftp.session lib.sftp_aio_wait_read(handle_ptr, buffer_ptr, Csize_t(chunk_size))
                end
                if ret == SSH_ERROR
                    throw(SftpException("Reading file from $(pos):$(pos + chunk_size - 1)", file))
                end
            end
        end
    finally
        free_handles()
    end

    return out
end

"""
$(TYPEDSIGNATURES)

Read the whole file as a `String`.
"""
Base.read(file::SftpFile, ::Type{String}) = String(read(file))

"""
$(TYPEDSIGNATURES)

Write `data` to the remote file and returns the number of bytes written. This
uses libssh's asynchronous IO API so it may launch multiple parallel requests.

# Throws
- `ArgumentError`: If `file` is closed.
- [`SftpException`](@ref): If writing fails.
"""
function Base.write(file::SftpFile, data::T) where T <: DenseVector
    if !isopen(file)
        throw(ArgumentError("$file is closed, cannot write to it"))
    end

    handles = Base.RefValue{lib.sftp_aio}[]
    free_handles = () -> map(x -> lib.sftp_aio_free(x[]), handles)

    # Launch requests
    bytes_left = sizeof(data)
    try
        while bytes_left > 0
            handle = Ref{lib.sftp_aio}()
            offset = length(data) - bytes_left
            ret = GC.@preserve data lib.sftp_aio_begin_write(file, Ptr{Cvoid}(pointer(data)) + offset, bytes_left, handle)
            if ret == SSH_ERROR
                throw(SftpException("Attempted write to file failed", file))
            end

            push!(handles, handle)
            bytes_left -= ret
        end
    catch
        free_handles()
        rethrow()
    end

    # Wait for the requests to be completed
    try
        for handle in handles
            GC.@preserve handle begin
                handle_ptr = Base.unsafe_convert(Ptr{lib.sftp_aio}, handle)
                ret = _session_trywait(file.sftp.session) do
                    @lockandblock file.sftp.session lib.sftp_aio_wait_write(handle_ptr)
                end
                if ret == SSH_ERROR
                    throw(SftpException("Write to file failed", file))
                end
            end
        end
    finally
        free_handles()
    end

    # At this point we should have written all the data
    return sizeof(data)
end

"""
$(TYPEDSIGNATURES)

Write a string directly to `file`. Uses [`Base.write(::SftpFile,
::DenseVector)`](@ref) internally.
"""
Base.write(file::SftpFile, data::AbstractString) = write(file, codeunits(data))

## SftpException

"""
$(TYPEDEF)
$(TYPEDFIELDS)

Represents an error from the SFTP subsystem.
"""
struct SftpException <: Exception
    msg::String
    path::Union{String, Nothing}
    error_code::SftpError
    session_error::String
    session_userhost::String
end

function SftpException(msg::AbstractString, path, sftp::SftpSession)
    userhost = "$(sftp.session.user)@$(sftp.session.host)"
    return SftpException(msg, path, get_error(sftp), get_error(sftp.session), userhost)
end

function SftpException(msg::AbstractString, sftp::SftpSession)
    SftpException(msg, nothing, sftp)
end

function SftpException(msg::AbstractString, file::SftpFile)
    SftpException(msg, file.path, file.sftp)
end

function Base.show(io::IO, ex::SftpException)
    print(io,
          """
          SftpException: $(ex.msg) ($(ex.error_code))
            Session error: '$(ex.session_error)'
            User/host: $(ex.session_userhost)
          """)
    if !isnothing(ex.path)
        print(io, "  Remote path: $(ex.path)")
    end
end
