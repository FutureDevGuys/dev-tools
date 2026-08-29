use std::ffi::{c_void, OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::io::{Seek, SeekFrom};
use std::mem::{offset_of, size_of};
use std::ops::{Deref, DerefMut};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf, Prefix};
use std::ptr::{null, null_mut};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS,
    ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SetEntriesInAclW, EXPLICIT_ACCESS_W, SET_ACCESS, SE_FILE_OBJECT,
    TRUSTEE_IS_SID, TRUSTEE_IS_USER, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, CopySid, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetTokenInformation, InitializeSecurityDescriptor, IsValidAcl,
    IsValidSecurityDescriptor, IsValidSid, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
    SetSecurityDescriptorOwner, TokenUser, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSID,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SE_DACL_PRESENT, SE_DACL_PROTECTED,
    SUB_CONTAINERS_AND_OBJECTS_INHERIT, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileAttributeTagInfo, FileStandardInfo, GetDriveTypeW,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, GetVolumeInformationW, MoveFileExW,
    CREATE_NEW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_NAME_NORMALIZED,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO,
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, OPEN_ALWAYS, OPEN_EXISTING, READ_CONTROL,
    VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, FILE_PERSISTENT_ACLS, SECURITY_DESCRIPTOR_REVISION,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

const ALL_SHARES: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ObjectKind {
    File,
    Directory,
}

impl ObjectKind {
    fn ace_flags(self) -> u8 {
        match self {
            Self::File => 0,
            Self::Directory => SUB_CONTAINERS_AND_OBJECTS_INHERIT as u8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AclPolicyObservation {
    owner_is_current_user: bool,
    dacl_is_present: bool,
    dacl_is_protected: bool,
    ace_count: u32,
    ace_type: u8,
    ace_flags: u8,
    access_mask: u32,
    ace_is_current_user: bool,
}

fn matches_private_acl_policy(observed: AclPolicyObservation, kind: ObjectKind) -> bool {
    observed.owner_is_current_user
        && observed.dacl_is_present
        && observed.dacl_is_protected
        && observed.ace_count == 1
        && observed.ace_type == ACCESS_ALLOWED_ACE_TYPE as u8
        && observed.ace_flags == kind.ace_flags()
        && observed.access_mask == FILE_ALL_ACCESS
        && observed.ace_is_current_user
}

struct OwnedWinHandle(HANDLE);

impl Drop for OwnedWinHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper is constructed only for a non-null owned Win32 handle.
        // It owns that handle and closes it exactly once here.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

pub(super) struct ProgramGuard {
    file: File,
    _ancestor_handles: Vec<OwnedWinHandle>,
}

impl Deref for ProgramGuard {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

impl DerefMut for ProgramGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.file
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: SetEntriesInAclW and GetSecurityInfo allocate these pointers with
        // LocalAlloc. This owner is created only after a successful call and frees the
        // allocation exactly once after all interior pointers are no longer used.
        unsafe {
            LocalFree(self.0);
        }
    }
}

struct CurrentUserSid {
    words: Vec<u32>,
}

impl CurrentUserSid {
    fn load() -> io::Result<Self> {
        let mut token = null_mut();
        // SAFETY: GetCurrentProcess returns a process pseudo-handle valid for this call,
        // and token points to writable storage for the returned owned token handle.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedWinHandle(token);

        let mut required = 0;
        // SAFETY: the null buffer and zero length are the documented size-query form;
        // required points to initialized writable storage.
        let first =
            unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required) };
        if first != 0 {
            return Err(invalid_data("token-user size query unexpectedly succeeded"));
        }
        // SAFETY: GetLastError is read immediately after the failed Win32 call above.
        let size_error = unsafe { GetLastError() };
        if size_error != ERROR_INSUFFICIENT_BUFFER || required < size_of::<TOKEN_USER>() as u32 {
            return Err(io::Error::from_raw_os_error(size_error as i32));
        }

        let word_size = size_of::<usize>();
        let byte_capacity = (required as usize)
            .checked_add(word_size - 1)
            .ok_or_else(|| invalid_data("token-user information length overflow"))?;
        let mut token_words = vec![0usize; byte_capacity / word_size];
        let buffer_len = token_words
            .len()
            .checked_mul(word_size)
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| invalid_data("token-user information is too large"))?;
        let mut returned = 0;
        // SAFETY: token_words is aligned at least as strictly as TOKEN_USER, its byte
        // capacity is buffer_len, and the token and output-length pointers are valid.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                token_words.as_mut_ptr().cast(),
                buffer_len,
                &mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if returned < size_of::<TOKEN_USER>() as u32 || returned > buffer_len {
            return Err(invalid_data("token-user information has an invalid length"));
        }

        // SAFETY: the successful GetTokenInformation call initialized at least one
        // aligned TOKEN_USER value at the beginning of token_words.
        let sid = unsafe { (*token_words.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let start = token_words.as_ptr() as usize;
        let end = start
            .checked_add(returned as usize)
            .ok_or_else(|| invalid_data("token-user information address overflow"))?;
        let sid_len = bounded_sid_length(sid, start, end)
            .ok_or_else(|| invalid_data("current-user SID is outside token information"))?;

        let sid_word_count = (sid_len as usize)
            .checked_add(size_of::<u32>() - 1)
            .ok_or_else(|| invalid_data("current-user SID length overflow"))?
            / size_of::<u32>();
        let mut words = vec![0u32; sid_word_count];
        // SAFETY: words has at least sid_len writable bytes and sid was validated as a
        // complete SID inside the live token-information buffer.
        if unsafe { CopySid(sid_len, words.as_mut_ptr().cast(), sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { words })
    }

    fn as_psid(&self) -> PSID {
        self.words.as_ptr().cast_mut().cast()
    }
}

fn bounded_sid_length(sid: PSID, start: usize, end: usize) -> Option<u32> {
    let address = sid as usize;
    let header_end = address.checked_add(8)?;
    if address < start || header_end > end {
        return None;
    }
    // SAFETY: the range checks above prove that the fixed eight-byte SID header is
    // entirely inside the caller-provided live allocation.
    let header = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), 8) };
    let length = 8usize.checked_add(usize::from(header[1]).checked_mul(4)?)?;
    if address.checked_add(length)? > end {
        return None;
    }
    // SAFETY: the computed SID extent is inside the allocation, so IsValidSid and
    // GetLengthSid may inspect the full candidate without reading beyond it.
    if unsafe { IsValidSid(sid) } == 0 || unsafe { GetLengthSid(sid) } as usize != length {
        return None;
    }
    u32::try_from(length).ok()
}

struct PrivateSecurityAttributes {
    descriptor: Box<SECURITY_DESCRIPTOR>,
    _acl: LocalAllocation,
    _user: CurrentUserSid,
}

impl PrivateSecurityAttributes {
    fn new(kind: ObjectKind) -> io::Result<Self> {
        let user = CurrentUserSid::load()?;
        let trustee = TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: user.as_psid().cast(),
        };
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_ALL_ACCESS,
            grfAccessMode: SET_ACCESS,
            grfInheritance: u32::from(kind.ace_flags()),
            Trustee: trustee,
        };
        let mut acl = null_mut::<ACL>();
        // SAFETY: entry and its trustee are initialized, the trustee SID is valid for
        // the duration of the call, and acl points to writable output storage.
        let status = unsafe { SetEntriesInAclW(1, &entry, null(), &mut acl) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if acl.is_null() {
            return Err(invalid_data("ACL construction returned a null ACL"));
        }
        let acl_owner = LocalAllocation(acl.cast());

        let mut descriptor = Box::<SECURITY_DESCRIPTOR>::default();
        let descriptor_ptr = (&mut *descriptor as *mut SECURITY_DESCRIPTOR).cast();
        // SAFETY: descriptor_ptr identifies suitably aligned writable storage for an
        // absolute SECURITY_DESCRIPTOR owned by descriptor.
        if unsafe { InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: descriptor has been initialized and the current-user SID allocation
        // remains live in the returned owner for every use of the descriptor.
        if unsafe { SetSecurityDescriptorOwner(descriptor_ptr, user.as_psid(), 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: descriptor is initialized and acl_owner holds the valid ACL allocation
        // live for every use of the descriptor. The DACL is present and not defaulted.
        if unsafe { SetSecurityDescriptorDacl(descriptor_ptr, 1, acl, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: descriptor is initialized; this marks its DACL protected so no parent
        // ACEs can be inherited in addition to the single current-user ACE.
        if unsafe {
            SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: descriptor, ACL, and owner SID are all initialized and live here.
        if unsafe { IsValidSecurityDescriptor(descriptor_ptr) } == 0 {
            return Err(invalid_data("constructed security descriptor is invalid"));
        }

        Ok(Self {
            descriptor,
            _acl: acl_owner,
            _user: user,
        })
    }

    fn attributes(&mut self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: (&mut *self.descriptor as *mut SECURITY_DESCRIPTOR).cast(),
            bInheritHandle: 0,
        }
    }
}

pub(super) fn validate_private_directory(path: &Path) -> io::Result<()> {
    let _ancestor_handles = validate_local_input_path(path)?;
    let wide = nul_terminated(path.as_os_str())?;
    // SAFETY: wide is NUL-terminated, all pointers are valid for the call, and no raw
    // handle escapes before it is placed under OwnedWinHandle ownership.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            ALL_SHARES,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    let handle = owned_handle(handle)?;
    validate_open_handle(handle.0, ObjectKind::Directory)
}

pub(super) fn open_private_file(path: &Path) -> io::Result<File> {
    let _ancestor_handles = validate_local_input_path(path)?;
    let wide = nul_terminated(path.as_os_str())?;
    // SAFETY: wide is NUL-terminated and all other arguments follow CreateFileW's
    // contract. FILE_FLAG_OPEN_REPARSE_POINT keeps the final component untraversed.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ,
            ALL_SHARES,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    file_from_validated_handle(handle)
}

pub(super) fn validate_local_program(path: &Path) -> io::Result<()> {
    drop(open_local_regular_file(
        path,
        FILE_READ_ATTRIBUTES,
        ALL_SHARES,
    )?);
    Ok(())
}

pub(super) fn lock_local_program(path: &Path) -> io::Result<ProgramGuard> {
    open_local_regular_file(path, FILE_READ_ATTRIBUTES, FILE_SHARE_READ)
}

pub(super) fn lock_local_program_for_copy(path: &Path) -> io::Result<ProgramGuard> {
    open_local_regular_file(path, FILE_GENERIC_READ, FILE_SHARE_READ)
}

fn open_local_regular_file(
    path: &Path,
    desired_access: u32,
    share_mode: u32,
) -> io::Result<ProgramGuard> {
    let ancestor_handles = validate_local_input_path_on_fixed_drive(path, true)?;
    let wide = nul_terminated(path.as_os_str())?;
    // SAFETY: wide is NUL-terminated and all other arguments follow CreateFileW's
    // contract. Opening the final component as a reparse point makes the subsequent
    // attribute check authoritative without following a final link.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            desired_access,
            share_mode,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a new owned, valid handle. File assumes that single
    // ownership and closes the handle on every success or validation-error path.
    let file = unsafe { File::from_raw_handle(handle) };
    validate_local_regular_handle(file.as_raw_handle())?;
    Ok(ProgramGuard {
        file,
        _ancestor_handles: ancestor_handles,
    })
}

pub(super) fn open_or_create_private_file(path: &Path) -> io::Result<File> {
    let _ancestor_handles = validate_local_input_path(path)?;
    let wide = nul_terminated(path.as_os_str())?;
    let mut security = PrivateSecurityAttributes::new(ObjectKind::File)?;
    let attributes = security.attributes();
    // SAFETY: wide and attributes are initialized and remain live for the synchronous
    // call. The descriptor's SID and ACL owners in security also remain live. Existing
    // objects are opened without changing their ACL and are validated before return.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            ALL_SHARES,
            &attributes,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    file_from_validated_handle(handle)
}

#[cfg(test)]
pub(super) fn copy_to_private_replacement(source: &Path, destination: &Path) -> io::Result<()> {
    let mut source_file = lock_local_program_for_copy(source)?;
    copy_open_file_to_private_replacement(&mut source_file, destination)
}

pub(super) fn copy_open_file_to_private_replacement(
    source: &mut File,
    destination: &Path,
) -> io::Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| invalid_input("private replacement has no parent directory"))?;
    let _ancestor_handles = validate_local_input_path(destination)?;
    validate_private_directory(parent)?;
    source.seek(SeekFrom::Start(0))?;
    let source_length = source.metadata()?.len();
    match fs::symlink_metadata(destination) {
        Ok(_) => fs::remove_file(destination)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut destination_file = create_new_private_file(destination)?;
    let result = (|| {
        let copied = io::copy(source, &mut destination_file)?;
        if copied != source_length {
            return Err(invalid_data("private file copy changed length"));
        }
        destination_file.sync_all()
    })();
    let _ = source.seek(SeekFrom::Start(0));
    drop(destination_file);
    if result.is_err() {
        let _ = fs::remove_file(destination);
    }
    result
}

pub(super) fn atomically_replace_private_file(
    replacement: &Path,
    destination: &Path,
) -> io::Result<()> {
    if replacement.parent().is_none() || replacement.parent() != destination.parent() {
        return Err(invalid_input(
            "private replacement and destination must share a directory",
        ));
    }
    let _ancestor_handles = validate_local_input_path(destination)?;
    let parent = replacement
        .parent()
        .ok_or_else(|| invalid_input("private replacement has no parent directory"))?;
    validate_private_directory(parent)?;
    drop(open_private_file(replacement)?);
    let replacement_wide = nul_terminated(replacement.as_os_str())?;
    let destination_wide = nul_terminated(destination.as_os_str())?;
    // SAFETY: both paths are NUL-terminated. The replacement is a validated private file
    // in the validated private destination directory. MOVEFILE_REPLACE_EXISTING replaces
    // rather than adopts any old destination and retains the replacement file's DACL.
    if unsafe {
        MoveFileExW(
            replacement_wide.as_ptr(),
            destination_wide.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    drop(open_private_file(destination)?);
    Ok(())
}

pub(super) fn ensure_private_directory(path: &Path) -> io::Result<()> {
    let _ancestor_handles = validate_local_input_path(path)?;
    let wide = nul_terminated(path.as_os_str())?;
    let mut security = PrivateSecurityAttributes::new(ObjectKind::Directory)?;
    let attributes = security.attributes();
    // SAFETY: wide and attributes are initialized and remain live for the synchronous
    // call, including the descriptor's owner SID and ACL backing allocations.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        // SAFETY: GetLastError is read immediately after CreateDirectoryW failed.
        let error = unsafe { GetLastError() };
        if error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS {
            return Err(io::Error::from_raw_os_error(error as i32));
        }
    }
    // Whether this call created the directory or lost a race to an existing object,
    // validate the opened object. Unsafe existing ACLs are never replaced or adopted.
    validate_private_directory(path)
}

pub(super) fn ensure_private_directory_all(path: &Path) -> io::Result<()> {
    let _ancestor_handles = validate_local_input_path(path)?;
    let mut missing = Vec::<PathBuf>::new();
    let mut current = path;
    loop {
        match fs::symlink_metadata(current) {
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(current.to_path_buf());
                current = current
                    .parent()
                    .ok_or_else(|| invalid_input("private directory has no existing ancestor"))?;
            }
            Err(error) => return Err(error),
        }
    }
    for directory in missing.iter().rev() {
        ensure_private_directory(directory)?;
    }
    ensure_private_directory(path)
}

pub(super) fn create_private_named_pipe(
    name: &OsStr,
    first_instance: bool,
) -> io::Result<NamedPipeServer> {
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true);
    let mut security = PrivateSecurityAttributes::new(ObjectKind::File)?;
    let mut attributes = security.attributes();
    // SAFETY: attributes points to a live SECURITY_ATTRIBUTES value for this synchronous
    // CreateNamedPipeW call. security retains the descriptor, ACL, and current-user SID
    // through the call; Windows copies the descriptor into the new pipe object.
    unsafe {
        options.create_with_security_attributes_raw(
            name,
            (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
        )
    }
}

fn file_from_validated_handle(handle: HANDLE) -> io::Result<File> {
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a new owned, valid handle. File assumes that single
    // ownership and closes the handle on every success or validation-error path.
    let file = unsafe { File::from_raw_handle(handle) };
    validate_open_handle(file.as_raw_handle(), ObjectKind::File)?;
    Ok(file)
}

fn create_new_private_file(path: &Path) -> io::Result<File> {
    let _ancestor_handles = validate_local_input_path(path)?;
    let wide = nul_terminated(path.as_os_str())?;
    let mut security = PrivateSecurityAttributes::new(ObjectKind::File)?;
    let attributes = security.attributes();
    // SAFETY: wide and attributes are initialized and live for this synchronous call;
    // CREATE_NEW prevents adopting any pre-existing object's ACL.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            ALL_SHARES,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    file_from_validated_handle(handle)
}

fn owned_handle(handle: HANDLE) -> io::Result<OwnedWinHandle> {
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(OwnedWinHandle(handle))
    }
}

fn validate_open_handle(handle: HANDLE, kind: ObjectKind) -> io::Result<()> {
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: handle is live and attributes is writable storage of the exact requested
    // FILE_ATTRIBUTE_TAG_INFO size.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) != 0 {
        return Err(permission_denied(
            "private object must not be a reparse point or device",
        ));
    }

    let mut standard = FILE_STANDARD_INFO::default();
    // SAFETY: handle is live and standard is writable storage of the exact requested
    // FILE_STANDARD_INFO size.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if standard.Directory != (kind == ObjectKind::Directory) {
        return Err(permission_denied("private object has the wrong type"));
    }
    if kind == ObjectKind::File && standard.NumberOfLinks != 1 {
        return Err(permission_denied(
            "private file must have exactly one hard link",
        ));
    }

    validate_final_handle_path(handle)?;
    validate_private_security(handle, kind)
}

fn validate_local_regular_handle(handle: HANDLE) -> io::Result<()> {
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: handle is live and attributes is exact writable output storage.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) != 0 {
        return Err(permission_denied(
            "program must not be a reparse point or device",
        ));
    }
    let mut standard = FILE_STANDARD_INFO::default();
    // SAFETY: handle is live and standard is exact writable output storage.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if standard.Directory {
        return Err(permission_denied("program path must be a regular file"));
    }
    validate_final_handle_path_with_policy(handle, true)
}

fn validate_private_security(handle: HANDLE, kind: ObjectKind) -> io::Result<()> {
    let user = CurrentUserSid::load()?;
    let mut owner = null_mut();
    let mut dacl = null_mut::<ACL>();
    let mut descriptor = null_mut::<c_void>();
    // SAFETY: handle was opened with READ_CONTROL, all requested output slots are valid,
    // and unrequested group/SACL outputs are null. A successful descriptor is LocalFree-owned.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    if descriptor.is_null() {
        return Err(invalid_data("security query returned a null descriptor"));
    }
    let _descriptor_owner = LocalAllocation(descriptor);

    // SAFETY: descriptor is the live descriptor returned by GetSecurityInfo.
    if unsafe { IsValidSecurityDescriptor(descriptor) } == 0 {
        return Err(permission_denied(
            "private object has an invalid descriptor",
        ));
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    // SAFETY: descriptor is valid and both output pointers identify initialized writable
    // scalars for the duration of the call.
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if revision != SECURITY_DESCRIPTOR_REVISION {
        return Err(permission_denied(
            "private object has an unsupported descriptor revision",
        ));
    }

    // SAFETY: owner came from the valid live descriptor. IsValidSid is checked before
    // EqualSid compares it with the separately owned current-user SID.
    let owner_matches = !owner.is_null()
        && unsafe { IsValidSid(owner) } != 0
        && unsafe { EqualSid(owner, user.as_psid()) } != 0;
    let mut observed = AclPolicyObservation {
        owner_is_current_user: owner_matches,
        dacl_is_present: control & SE_DACL_PRESENT != 0 && !dacl.is_null(),
        dacl_is_protected: control & SE_DACL_PROTECTED != 0,
        ace_count: 0,
        ace_type: u8::MAX,
        ace_flags: u8::MAX,
        access_mask: 0,
        ace_is_current_user: false,
    };

    // SAFETY: dacl is non-null only when it points inside the valid live descriptor.
    if !observed.dacl_is_present || unsafe { IsValidAcl(dacl) } == 0 {
        return Err(permission_denied(
            "private object must have one protected current-user DACL entry",
        ));
    }
    let mut acl_size = ACL_SIZE_INFORMATION::default();
    // SAFETY: dacl is valid and acl_size is exact writable output storage.
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut acl_size as *mut ACL_SIZE_INFORMATION).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    observed.ace_count = acl_size.AceCount;
    if observed.ace_count == 1 {
        let mut ace = null_mut::<c_void>();
        // SAFETY: dacl is valid, index zero is in range, and ace is writable output storage.
        if unsafe { GetAce(dacl, 0, &mut ace) } == 0 || ace.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: GetAce on a valid ACL returned a pointer to an ACE whose header is
        // contained in that ACL. read_unaligned avoids assuming stronger alignment.
        let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
        observed.ace_type = header.AceType;
        observed.ace_flags = header.AceFlags;

        let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let minimum_ace_size = sid_offset + 8;
        if header.AceType == ACCESS_ALLOWED_ACE_TYPE as u8
            && usize::from(header.AceSize) >= minimum_ace_size
        {
            // SAFETY: the valid ACE has enough bytes for its header and mask at the
            // declared ACCESS_ALLOWED_ACE offsets.
            observed.access_mask = unsafe {
                ace.cast::<u8>()
                    .add(offset_of!(ACCESS_ALLOWED_ACE, Mask))
                    .cast::<u32>()
                    .read_unaligned()
            };
            // SAFETY: the size check proves a minimum SID header is present at SidStart;
            // bounded_sid_length validates the full variable-length SID before EqualSid.
            let ace_sid = unsafe { ace.cast::<u8>().add(sid_offset).cast::<c_void>() };
            let ace_start = ace as usize;
            let ace_end = ace_start
                .checked_add(usize::from(header.AceSize))
                .ok_or_else(|| invalid_data("ACL entry address overflow"))?;
            if bounded_sid_length(ace_sid, ace_start, ace_end).is_some() {
                // SAFETY: bounded_sid_length validated ace_sid, and user owns a valid SID.
                observed.ace_is_current_user = unsafe { EqualSid(ace_sid, user.as_psid()) } != 0;
            }
        }
    }

    if matches_private_acl_policy(observed, kind) {
        Ok(())
    } else {
        Err(permission_denied(
            "private object must be current-user owned with one protected full-control ACE",
        ))
    }
}

fn validate_local_input_path(path: &Path) -> io::Result<Vec<OwnedWinHandle>> {
    validate_local_input_path_on_fixed_drive(path, true)
}

fn validate_local_input_path_on_fixed_drive(
    path: &Path,
    require_persistent_acls: bool,
) -> io::Result<Vec<OwnedWinHandle>> {
    let drive = local_disk_drive(path, false)
        .ok_or_else(|| invalid_input("private path must be an absolute local drive path"))?;
    validate_fixed_drive(drive)?;
    if require_persistent_acls {
        validate_persistent_acls(drive)?;
    }
    open_existing_ancestor_handles(path)
}

fn open_existing_ancestor_handles(path: &Path) -> io::Result<Vec<OwnedWinHandle>> {
    let mut ancestors = Vec::new();
    let mut current = path.parent();
    while let Some(ancestor) = current {
        ancestors.push(ancestor);
        current = ancestor.parent();
    }
    ancestors.reverse();

    let mut handles = Vec::with_capacity(ancestors.len());
    for ancestor in ancestors {
        let wide = nul_terminated(ancestor.as_os_str())?;
        // SAFETY: wide is NUL-terminated and all other arguments follow CreateFileW's
        // contract. OPEN_REPARSE_POINT makes the cumulative ancestor the untraversed
        // final component, and the returned raw handle is immediately given one owner.
        let raw_handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ,
                null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                null_mut(),
            )
        };
        let handle = match owned_handle(raw_handle) {
            Ok(handle) => handle,
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error),
        };
        validate_ancestor_handle(handle.0)?;
        handles.push(handle);
    }
    Ok(handles)
}

fn validate_ancestor_handle(handle: HANDLE) -> io::Result<()> {
    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: handle is live and attributes is writable storage of the exact requested
    // FILE_ATTRIBUTE_TAG_INFO size.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE) != 0 {
        return Err(permission_denied(
            "path ancestor must not be a reparse point or device",
        ));
    }

    let mut standard = FILE_STANDARD_INFO::default();
    // SAFETY: handle is live and standard is writable storage of the exact requested
    // FILE_STANDARD_INFO size.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if !standard.Directory {
        return Err(permission_denied("path ancestor must be a directory"));
    }
    Ok(())
}

fn local_disk_drive(path: &Path, allow_verbatim_disk: bool) -> Option<u8> {
    let mut components = path.components();
    let drive = match components.next()? {
        Component::Prefix(prefix) => match prefix.kind() {
            Prefix::Disk(drive) => drive,
            Prefix::VerbatimDisk(drive) if allow_verbatim_disk => drive,
            Prefix::UNC(_, _)
            | Prefix::VerbatimUNC(_, _)
            | Prefix::DeviceNS(_)
            | Prefix::Verbatim(_) => return None,
            Prefix::VerbatimDisk(_) => return None,
        },
        _ => return None,
    };
    if components.next() != Some(Component::RootDir) {
        return None;
    }
    for component in components {
        match component {
            Component::Normal(value) if valid_normal_component(value) => {}
            _ => return None,
        }
    }
    Some(drive)
}

fn valid_normal_component(value: &OsStr) -> bool {
    let wide: Vec<u16> = value.encode_wide().collect();
    if wide.is_empty()
        || wide.iter().any(|unit| *unit == 0 || *unit == b':' as u16)
        || wide.last().is_some_and(|unit| matches!(*unit, 0x20 | 0x2e))
    {
        return false;
    }
    !is_dos_device_name(&wide)
}

fn is_dos_device_name(wide: &[u16]) -> bool {
    let stem_end = wide
        .iter()
        .position(|unit| *unit == b'.' as u16)
        .unwrap_or(wide.len());
    let stem = &wide[..stem_end];
    let equals_ascii = |expected: &[u8]| {
        stem.len() == expected.len()
            && stem.iter().zip(expected).all(|(actual, expected)| {
                u8::try_from(*actual).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
            })
    };
    equals_ascii(b"CON")
        || equals_ascii(b"PRN")
        || equals_ascii(b"AUX")
        || equals_ascii(b"NUL")
        || equals_ascii(b"CONIN$")
        || equals_ascii(b"CONOUT$")
        || equals_ascii(b"CLOCK$")
        || (stem.len() == 4
            && (stem[..3].iter().zip(b"COM").all(|(actual, expected)| {
                u8::try_from(*actual).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
            }) || stem[..3].iter().zip(b"LPT").all(|(actual, expected)| {
                u8::try_from(*actual).is_ok_and(|actual| actual.eq_ignore_ascii_case(expected))
            }))
            && matches!(stem[3], 0x31..=0x39 | 0x00b9 | 0x00b2 | 0x00b3))
}

fn drive_root(drive: u8) -> [u16; 4] {
    [
        u16::from(drive.to_ascii_uppercase()),
        b':' as u16,
        b'\\' as u16,
        0,
    ]
}

fn validate_fixed_drive(drive: u8) -> io::Result<()> {
    let root = drive_root(drive);
    // SAFETY: root is a valid NUL-terminated drive-root string.
    if unsafe { GetDriveTypeW(root.as_ptr()) } != DRIVE_FIXED {
        return Err(permission_denied("path must reside on a fixed local drive"));
    }
    Ok(())
}

fn validate_persistent_acls(drive: u8) -> io::Result<()> {
    let root = drive_root(drive);
    let mut flags = 0u32;
    // SAFETY: root is NUL-terminated, optional output buffers are null with zero sizes,
    // and flags points to writable storage.
    if unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            null_mut(),
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if !volume_supports_persistent_acls(flags) {
        return Err(permission_denied(
            "private path volume does not preserve access-control lists",
        ));
    }
    Ok(())
}

fn volume_supports_persistent_acls(flags: u32) -> bool {
    flags & FILE_PERSISTENT_ACLS != 0
}

fn validate_final_handle_path(handle: HANDLE) -> io::Result<()> {
    validate_final_handle_path_with_policy(handle, true)
}

fn validate_final_handle_path_with_policy(
    handle: HANDLE,
    require_persistent_acls: bool,
) -> io::Result<()> {
    let final_path = final_path_name(handle)?;
    let drive = local_disk_drive(&final_path, true).ok_or_else(|| {
        permission_denied("private object resolved to a UNC, device, or non-drive path")
    })?;
    validate_fixed_drive(drive)?;
    if require_persistent_acls {
        validate_persistent_acls(drive)?;
    }
    Ok(())
}

fn final_path_name(handle: HANDLE) -> io::Result<PathBuf> {
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    // SAFETY: handle is live and the null/zero buffer is the documented size query.
    let required = unsafe { GetFinalPathNameByHandleW(handle, null_mut(), 0, flags) };
    if required == 0 {
        return Err(io::Error::last_os_error());
    }
    let initial = usize::try_from(required)
        .ok()
        .and_then(|length| length.checked_add(1))
        .ok_or_else(|| invalid_data("final path length overflow"))?;
    let mut buffer = vec![0u16; initial];
    loop {
        let capacity =
            u32::try_from(buffer.len()).map_err(|_| invalid_data("final path is too large"))?;
        // SAFETY: buffer contains capacity writable UTF-16 code units and handle is live.
        let written =
            unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), capacity, flags) };
        if written == 0 {
            return Err(io::Error::last_os_error());
        }
        if written < capacity {
            buffer.truncate(written as usize);
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        let next = usize::try_from(written)
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| invalid_data("final path length overflow"))?;
        buffer.resize(next, 0);
    }
}

fn nul_terminated(value: &OsStr) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) {
        return Err(invalid_input("Windows path contains a NUL code unit"));
    }
    wide.push(0);
    Ok(wide)
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn permission_denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_directory_symlink(target: &Path, link: &Path) -> bool {
        match std::os::windows::fs::symlink_dir(target, link) {
            Ok(()) => true,
            Err(error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    || error.raw_os_error()
                        == Some(
                            windows_sys::Win32::Foundation::ERROR_PRIVILEGE_NOT_HELD as i32,
                        ) =>
            {
                eprintln!(
                    "skipping directory-symlink test because Windows denied creation: {error}"
                );
                false
            }
            Err(error) => panic!("create test directory symlink: {error}"),
        }
    }

    fn accepted_policy(kind: ObjectKind) -> AclPolicyObservation {
        AclPolicyObservation {
            owner_is_current_user: true,
            dacl_is_present: true,
            dacl_is_protected: true,
            ace_count: 1,
            ace_type: ACCESS_ALLOWED_ACE_TYPE as u8,
            ace_flags: kind.ace_flags(),
            access_mask: FILE_ALL_ACCESS,
            ace_is_current_user: true,
        }
    }

    #[test]
    fn acl_policy_accepts_exactly_one_current_user_full_control_ace() {
        assert!(matches_private_acl_policy(
            accepted_policy(ObjectKind::File),
            ObjectKind::File
        ));
        assert!(matches_private_acl_policy(
            accepted_policy(ObjectKind::Directory),
            ObjectKind::Directory
        ));
    }

    #[test]
    fn acl_policy_rejects_each_weakened_property() {
        let expected = accepted_policy(ObjectKind::File);
        let weakened = [
            AclPolicyObservation {
                owner_is_current_user: false,
                ..expected
            },
            AclPolicyObservation {
                dacl_is_present: false,
                ..expected
            },
            AclPolicyObservation {
                dacl_is_protected: false,
                ..expected
            },
            AclPolicyObservation {
                ace_count: 2,
                ..expected
            },
            AclPolicyObservation {
                ace_type: 1,
                ..expected
            },
            AclPolicyObservation {
                ace_flags: SUB_CONTAINERS_AND_OBJECTS_INHERIT as u8,
                ..expected
            },
            AclPolicyObservation {
                access_mask: FILE_GENERIC_READ,
                ..expected
            },
            AclPolicyObservation {
                ace_is_current_user: false,
                ..expected
            },
        ];
        assert!(weakened
            .into_iter()
            .all(|observed| !matches_private_acl_policy(observed, ObjectKind::File)));
    }

    #[test]
    fn local_path_policy_rejects_unc_device_remote_forms_and_aliases() {
        assert_eq!(
            local_disk_drive(Path::new(r"C:\Users\example\dev-auth"), false),
            Some(b'C')
        );
        for rejected in [
            r"\\server\share\dev-auth",
            r"\\?\UNC\server\share\dev-auth",
            r"\\.\C:\dev-auth",
            r"\\?\C:\dev-auth",
            r"C:dev-auth",
            r"\dev-auth",
            r"C:\safe\..\dev-auth",
            r"C:\safe\token:stream",
            r"C:\safe\NUL.txt",
            r"C:\safe\COM1",
        ] {
            assert_eq!(local_disk_drive(Path::new(rejected), false), None);
        }
        assert_eq!(
            local_disk_drive(Path::new(r"\\?\C:\Users\example\dev-auth"), true),
            Some(b'C')
        );
    }

    #[test]
    fn credential_program_volume_policy_requires_persistent_acls() {
        assert!(!volume_supports_persistent_acls(0));
        assert!(volume_supports_persistent_acls(FILE_PERSISTENT_ACLS));
    }

    #[test]
    fn creates_and_reopens_private_directory_and_file() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("private");
        ensure_private_directory(&directory).unwrap();
        validate_private_directory(&directory).unwrap();

        let path = directory.join("lock");
        drop(open_or_create_private_file(&path).unwrap());
        drop(open_private_file(&path).unwrap());
    }

    #[test]
    fn replaces_existing_file_with_private_copy() {
        let temporary = tempfile::tempdir().unwrap();
        let directory = temporary.path().join("private");
        ensure_private_directory(&directory).unwrap();

        let source = temporary.path().join("source.exe");
        fs::write(&source, b"new executable").unwrap();
        validate_local_program(&source).unwrap();

        let destination = directory.join("child.exe");
        fs::write(&destination, b"old executable").unwrap();
        let replacement = directory.join(".child.exe.tmp");
        copy_to_private_replacement(&source, &replacement).unwrap();
        atomically_replace_private_file(&replacement, &destination).unwrap();

        let mut installed = open_private_file(&destination).unwrap();
        let mut contents = Vec::new();
        use std::io::Read as _;
        installed.read_to_end(&mut contents).unwrap();
        assert_eq!(contents, b"new executable");
        assert!(!replacement.exists());
    }

    #[test]
    fn program_guard_blocks_write_and_delete_until_drop() {
        let temporary = tempfile::tempdir().unwrap();
        let program = temporary.path().join("guarded.exe");
        fs::write(&program, b"executable").unwrap();

        let guard = lock_local_program(&program).unwrap();
        assert!(fs::OpenOptions::new().write(true).open(&program).is_err());
        assert!(fs::remove_file(&program).is_err());

        drop(guard);
        fs::remove_file(&program).unwrap();
    }

    #[test]
    fn program_path_rejects_directory_symlink_ancestor() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("program-target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("tool.exe"), b"executable").unwrap();
        let link = temporary.path().join("program-link");
        if !create_test_directory_symlink(&target, &link) {
            return;
        }

        let error = validate_local_program(&link.join("tool.exe")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn private_path_rejects_directory_symlink_ancestor() {
        let temporary = tempfile::tempdir().unwrap();
        let target = temporary.path().join("private-target");
        ensure_private_directory(&target).unwrap();
        drop(open_or_create_private_file(&target.join("secret")).unwrap());
        let link = temporary.path().join("private-link");
        if !create_test_directory_symlink(&target, &link) {
            return;
        }

        let error = open_private_file(&link.join("secret")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn creates_named_pipe_with_private_security_descriptor() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .unwrap();
        let _guard = runtime.enter();
        let name = format!(
            r"\\.\pipe\dev-auth-windows-security-test-{}",
            std::process::id()
        );
        let server = create_private_named_pipe(OsStr::new(&name), true).unwrap();
        validate_private_security(server.as_raw_handle(), ObjectKind::File).unwrap();
    }
}
