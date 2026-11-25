//! Windows access control lists (ACLs).
//!
//! A file or directory is private when its access list is *protected* (it inherits nothing
//! from its parent) and allows only the current user. Directories pass that access on to
//! files and folders created inside them, so files other programs create there (SQLite's
//! `-wal` and `-shm`) are private too.
//!
//! LocalSystem and the Administrators group are trusted the way root is on Unix: they can
//! take ownership of any file anyway, so an access entry for them does not make a file
//! readable by others.

use std::{
    ffi::c_void,
    fs, io,
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::Path,
    ptr,
};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, AddAccessAllowedAceEx,
        Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT, SetNamedSecurityInfoW},
        CONTAINER_INHERIT_ACE, CopySid, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid,
        GetAce, GetLengthSid, GetTokenInformation, INHERIT_ONLY_ACE, InitializeAcl,
        InitializeSecurityDescriptor, OBJECT_INHERIT_ACE, PROTECTED_DACL_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR,
        SECURITY_MAX_SID_SIZE, SetSecurityDescriptorControl, SetSecurityDescriptorDacl,
        TOKEN_QUERY, TOKEN_USER, TokenUser, WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid,
        WinLocalSystemSid,
    },
    Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

/// `ACCESS_ALLOWED_ACE_TYPE` and `ACCESS_ALLOWED_CALLBACK_ACE_TYPE`.
const ALLOW_ACE_TYPES: [u8; 2] = [0, 9];

/// Create a new private file for writing. Fails if `path` exists.
pub fn create_private_file(path: &Path) -> io::Result<fs::File> {
    let mut security = PrivateSecurity::new(false)?;
    let wide = wide(path);
    // SAFETY: `wide` is NUL-terminated and `security` lives through the call. The share mode
    // is std's default, so the file behaves like one from `File::create`.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            security.attributes(),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a valid handle we own; File closes it.
    Ok(unsafe { fs::File::from_raw_handle(handle) })
}

pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut missing = Vec::new();
    let mut next = Some(path);
    while let Some(dir) = next.filter(|dir| !dir.as_os_str().is_empty() && !dir.is_dir()) {
        missing.push(dir);
        next = dir.parent();
    }
    let mut security = PrivateSecurity::new(true)?;
    for dir in missing.into_iter().rev() {
        let wide = wide(dir);
        // SAFETY: `wide` is NUL-terminated and `security` lives through the call.
        if unsafe { CreateDirectoryW(wide.as_ptr(), security.attributes()) } == 0 {
            let err = io::Error::last_os_error();
            // Created concurrently: fine, as on Unix.
            if err.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) || !dir.is_dir() {
                return Err(err);
            }
        }
    }
    Ok(())
}

pub fn make_private(path: &Path) -> io::Result<()> {
    let acl = private_acl(&current_user()?, fs::metadata(path)?.is_dir())?;
    let wide = wide(path);
    // SAFETY: `wide` is NUL-terminated and `acl` is a valid ACL. A protected DACL stops
    // inheritance; for a directory, Windows passes the new entries on to its contents.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl.as_ptr().cast(),
            ptr::null(),
        )
    };
    win32_result(status)
}

pub fn is_readable_by_others(path: &Path) -> io::Result<bool> {
    let trusted = [
        current_user()?,
        well_known(WinLocalSystemSid)?,
        well_known(WinBuiltinAdministratorsSid)?,
    ];
    let dacl = Dacl::of(path)?;
    if dacl.acl.is_null() {
        // A missing access list grants everyone everything.
        return Ok(true);
    }
    // SAFETY: `dacl.acl` points at a valid ACL owned by `dacl`; GetAce only returns entries
    // inside it, and every entry starts with an ACE_HEADER.
    unsafe {
        for i in 0..u32::from((*dacl.acl).AceCount) {
            let mut ace: *mut c_void = ptr::null_mut();
            if GetAce(dacl.acl, i, &mut ace) == 0 {
                return Err(io::Error::last_os_error());
            }
            let header = &*ace.cast::<ACE_HEADER>();
            if !ALLOW_ACE_TYPES.contains(&header.AceType)
                || u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0
            {
                continue;
            }
            // Both allow types share ACCESS_ALLOWED_ACE's layout up to the SID. Like the Unix
            // check (mode & 0o077), any access at all counts, not only reading.
            let allowed = &*ace.cast::<ACCESS_ALLOWED_ACE>();
            let sid: PSID = (&raw const allowed.SidStart).cast_mut().cast();
            if allowed.Mask != 0 && !trusted.iter().any(|t| t.equals(sid)) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// How to fix a file that [`is_readable_by_others`] rejected.
pub fn restrict_hint(path: &Path) -> String {
    format!(
        "icacls \"{}\" /inheritance:r /grant:r \"%USERNAME%:F\"",
        path.display()
    )
}

/// A security descriptor for new files or directories: protected, current user only.
struct PrivateSecurity {
    // Boxed so the pointers in `attributes` stay valid when this struct moves.
    _acl: Box<[u64]>,
    descriptor: Box<SECURITY_DESCRIPTOR>,
    attributes: SECURITY_ATTRIBUTES,
}

impl PrivateSecurity {
    /// `inherit`: pass the access entry on to files and folders created inside.
    fn new(inherit: bool) -> io::Result<Self> {
        let mut acl = private_acl(&current_user()?, inherit)?;
        // SAFETY: SECURITY_DESCRIPTOR is plain data; Initialize… sets every field we rely on.
        let mut descriptor: Box<SECURITY_DESCRIPTOR> = Box::new(unsafe { std::mem::zeroed() });
        let sd: PSECURITY_DESCRIPTOR = (&raw mut *descriptor).cast();
        // SAFETY: `sd` points at the boxed descriptor; `acl` is a valid ACL kept alive in self.
        unsafe {
            check(InitializeSecurityDescriptor(sd, 1))?; // SECURITY_DESCRIPTOR_REVISION
            check(SetSecurityDescriptorDacl(sd, 1, acl.as_mut_ptr().cast(), 0))?;
            check(SetSecurityDescriptorControl(
                sd,
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            ))?;
        }
        Ok(Self {
            _acl: acl,
            attributes: SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            },
            descriptor,
        })
    }

    fn attributes(&mut self) -> *mut SECURITY_ATTRIBUTES {
        self.attributes.lpSecurityDescriptor = (&raw mut *self.descriptor).cast();
        &raw mut self.attributes
    }
}

/// An access list with one entry: full control for `user`.
fn private_acl(user: &Sid, inherit: bool) -> io::Result<Box<[u64]>> {
    let len = size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() + user.len();
    let mut buf = vec![0u64; len.div_ceil(8)].into_boxed_slice();
    let acl: *mut ACL = buf.as_mut_ptr().cast();
    let flags = if inherit {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    // SAFETY: `buf` is 8-byte aligned and `len` bytes long; `user` is a valid SID.
    unsafe {
        check(InitializeAcl(acl, len as u32, ACL_REVISION))?;
        check(AddAccessAllowedAceEx(
            acl,
            ACL_REVISION,
            flags,
            FILE_ALL_ACCESS,
            user.as_psid(),
        ))?;
    }
    Ok(buf)
}

/// A security identifier, copied into memory we own.
struct Sid(Box<[u32]>);

impl Sid {
    /// # Safety
    /// `sid` must point at a valid SID.
    unsafe fn copy(sid: PSID) -> io::Result<Self> {
        // SAFETY: the caller guarantees `sid` is valid; the buffer is GetLengthSid bytes.
        unsafe {
            let len = GetLengthSid(sid);
            let mut buf = vec![0u32; (len as usize).div_ceil(4)].into_boxed_slice();
            check(CopySid(len, buf.as_mut_ptr().cast(), sid))?;
            Ok(Self(buf))
        }
    }

    fn as_psid(&self) -> PSID {
        self.0.as_ptr().cast_mut().cast()
    }

    fn len(&self) -> usize {
        // SAFETY: always a valid SID.
        unsafe { GetLengthSid(self.as_psid()) as usize }
    }

    fn equals(&self, other: PSID) -> bool {
        // SAFETY: both are valid SIDs.
        unsafe { EqualSid(self.as_psid(), other) != 0 }
    }
}

fn current_user() -> io::Result<Sid> {
    // SAFETY: the token handle is closed on every path; the buffer is sized by the first
    // GetTokenInformation call and 8-byte aligned for TOKEN_USER.
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        check(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token,
        ))?;
        let mut len = 0;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
        let err = io::Error::last_os_error();
        CloseHandle(token);
        if ok == 0 {
            return Err(err);
        }
        Sid::copy((*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid)
    }
}

fn well_known(kind: WELL_KNOWN_SID_TYPE) -> io::Result<Sid> {
    let mut buf = [0u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(4)];
    let mut len = SECURITY_MAX_SID_SIZE;
    // SAFETY: `buf` holds SECURITY_MAX_SID_SIZE bytes.
    unsafe {
        check(CreateWellKnownSid(
            kind,
            ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        ))?;
        Sid::copy(buf.as_mut_ptr().cast())
    }
}

/// A file's access list, with the security descriptor that owns it.
struct Dacl {
    acl: *mut ACL,
    descriptor: PSECURITY_DESCRIPTOR,
}

impl Dacl {
    fn of(path: &Path) -> io::Result<Self> {
        let wide = wide(path);
        let mut dacl = Self {
            acl: ptr::null_mut(),
            descriptor: ptr::null_mut(),
        };
        // SAFETY: `wide` is NUL-terminated; the descriptor is freed in Drop.
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut dacl.acl,
                ptr::null_mut(),
                &mut dacl.descriptor,
            )
        };
        win32_result(status)?;
        Ok(dacl)
    }
}

impl Drop for Dacl {
    fn drop(&mut self) {
        // SAFETY: allocated by GetNamedSecurityInfoW, freed once.
        unsafe { LocalFree(self.descriptor.cast()) };
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

fn check(ok: impl Into<i32>) -> io::Result<()> {
    if ok.into() == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn win32_result(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

#[cfg(test)]
pub mod testing {
    //! Give the local Users group read access, the way `C:\ProgramData` does.

    use super::*;
    use windows_sys::Win32::Security::{
        Authorization::{
            EXPLICIT_ACCESS_W, GRANT_ACCESS, SetEntriesInAclW, TRUSTEE_IS_GROUP, TRUSTEE_IS_SID,
            TRUSTEE_W,
        },
        NO_INHERITANCE, SUB_CONTAINERS_AND_OBJECTS_INHERIT, WinBuiltinUsersSid,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;

    /// Add an entry letting the local Users group read `path` (and, for a directory, what is
    /// created inside it), keeping the entries it already has.
    pub fn grant_users_read(path: &Path) {
        let users = well_known(WinBuiltinUsersSid).unwrap();
        let old = Dacl::of(path).unwrap();
        let entry = EXPLICIT_ACCESS_W {
            grfAccessPermissions: FILE_GENERIC_READ,
            grfAccessMode: GRANT_ACCESS,
            grfInheritance: if path.is_dir() {
                SUB_CONTAINERS_AND_OBJECTS_INHERIT
            } else {
                NO_INHERITANCE
            },
            Trustee: TRUSTEE_W {
                pMultipleTrustee: ptr::null_mut(),
                MultipleTrusteeOperation: 0,
                TrusteeForm: TRUSTEE_IS_SID,
                TrusteeType: TRUSTEE_IS_GROUP,
                ptstrName: users.as_psid().cast(),
            },
        };
        let mut new: *mut ACL = ptr::null_mut();
        let wide = wide(path);
        // SAFETY: `entry` names a valid SID; `new` is freed below.
        unsafe {
            win32_result(SetEntriesInAclW(1, &entry, old.acl, &mut new)).unwrap();
            let status = SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                new,
                ptr::null(),
            );
            LocalFree(new.cast());
            win32_result(status).unwrap();
        }
    }
}
