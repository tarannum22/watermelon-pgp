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
//!
//! The owner can always change a file's access list. So an owner that isn't trusted counts as
//! access by others, even without an entry. The trusted owners are the current user, the
//! accounts above, and Windows service accounts (`NT SERVICE\…`, SIDs `S-1-5-80-…`), so that
//! an administrator can use a service's files. This matches the owner bits of a Unix mode.
//!
//! [`set_owner_and_restrict_to`] makes files private to another account instead, such as
//! the virtual account a Windows service runs as. [`allow_account`] adds an entry for an
//! account and keeps the others.

use std::{
    ffi::c_void,
    fs, io,
    mem::offset_of,
    os::windows::{ffi::OsStrExt, io::FromRawHandle},
    path::Path,
    ptr,
};

use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ALREADY_EXISTS, ERROR_NOT_ALL_ASSIGNED, GENERIC_WRITE, GetLastError,
        HANDLE, INVALID_HANDLE_VALUE, LUID, LocalFree,
    },
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, AddAccessAllowedAceEx,
        AdjustTokenPrivileges,
        Authorization::{
            ConvertSidToStringSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW,
            SE_FILE_OBJECT, SetEntriesInAclW, SetNamedSecurityInfoW, TRUSTEE_IS_SID,
            TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
        },
        CONTAINER_INHERIT_ACE, CopySid, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid,
        GetAce, GetLengthSid, GetTokenInformation, INHERIT_ONLY_ACE, INHERITED_ACE, InitializeAcl,
        InitializeSecurityDescriptor, LUID_AND_ATTRIBUTES, LookupAccountNameW, LookupAccountSidW,
        LookupPrivilegeValueW, NO_INHERITANCE, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
        SE_PRIVILEGE_ENABLED, SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE,
        SetSecurityDescriptorControl, SetSecurityDescriptorDacl, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER, TokenUser, WELL_KNOWN_SID_TYPE,
        WinBuiltinAdministratorsSid, WinCreatorOwnerSid, WinLocalSystemSid,
    },
    Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    },
    System::{
        SystemServices::{
            ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE, ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
            ACCESS_ALLOWED_OBJECT_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
        },
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

/// Allow entries laid out like ACCESS_ALLOWED_ACE: header, mask, then the SID.
const SIMPLE_ALLOW_TYPES: [u32; 2] = [ACCESS_ALLOWED_ACE_TYPE, ACCESS_ALLOWED_CALLBACK_ACE_TYPE];

/// Allow entries with other layouts. Unusual on files; rather than parse them, they count as
/// access by others, so the check fails closed.
const OTHER_ALLOW_TYPES: [u32; 3] = [
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
    ACCESS_ALLOWED_OBJECT_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
];

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

/// Replace `path`'s access list with a private one. For a directory, Windows also replaces
/// the *inherited* entries of everything inside it; entries set explicitly on a child, or a
/// child that blocks inheritance, keep their access.
pub fn make_private(path: &Path) -> io::Result<()> {
    let pass_on_to_contents = fs::metadata(path)?.is_dir();
    let acl = private_acl(&[&current_user()?], pass_on_to_contents)?;
    set_security(path, None, &acl)
}

/// Make `account` (`DOMAIN\name`) the owner of `path` and replace its access list so that
/// only `account`, LocalSystem and Administrators can access it. For a directory, the same goes
/// for everything inside it, now and created later.
///
/// Making another account the owner needs the restore privilege, which elevated
/// administrators have.
pub fn set_owner_and_restrict_to(path: &Path, account: &str) -> io::Result<()> {
    let account = Sid::of_account(account)?;
    enable_restore_privilege()?;
    let system = well_known(WinLocalSystemSid)?;
    let admins = well_known(WinBuiltinAdministratorsSid)?;
    set_owner_and_acl_recursively(path, &account, &[&account, &system, &admins])
}

fn set_owner_and_acl_recursively(path: &Path, owner: &Sid, allowed: &[&Sid]) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    // Links and junctions are left alone: they may point outside the data directory.
    if metadata.is_symlink() {
        return Ok(());
    }
    set_security(path, Some(owner), &private_acl(allowed, metadata.is_dir())?)?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            set_owner_and_acl_recursively(&entry?.path(), owner, allowed)?;
        }
    }
    Ok(())
}

/// Replace `path`'s access list with `acl`, protected from inheritance, and its owner if given.
fn set_security(path: &Path, owner: Option<&Sid>, acl: &[u64]) -> io::Result<()> {
    let mut info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    if owner.is_some() {
        info |= OWNER_SECURITY_INFORMATION;
    }
    let wide = wide(path);
    // SAFETY: `wide` is NUL-terminated, `acl` is a valid ACL and `owner` a valid SID.
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            info,
            owner.map_or(ptr::null_mut(), Sid::as_psid),
            ptr::null_mut(),
            acl.as_ptr().cast(),
            ptr::null(),
        )
    };
    check_status(status)
}

/// Add an entry to `path`'s access list allowing `account` to read it, or to read and write
/// it. Keeps the existing entries and the owner, so it suits files watermelon doesn't own, such
/// as a TLS certificate.
pub fn allow_account(path: &Path, account: &str, write: bool) -> io::Result<()> {
    let account = Sid::of_account(account)?;
    let access = if write {
        FILE_GENERIC_READ | FILE_GENERIC_WRITE
    } else {
        FILE_GENERIC_READ
    };
    add_allow_entry(path, &account, access, NO_INHERITANCE)
}

/// Add an allow entry for `sid` to `path`'s access list, keeping the others.
fn add_allow_entry(path: &Path, sid: &Sid, access: u32, inheritance: u32) -> io::Result<()> {
    let old = Dacl::of(path)?;
    let entry = EXPLICIT_ACCESS_W {
        grfAccessPermissions: access,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: inheritance,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.as_psid().cast(),
        },
    };
    let mut new: *mut ACL = ptr::null_mut();
    let wide = wide(path);
    // SAFETY: `entry` names a valid SID and `old.acl` is valid (or null); `new` is freed below.
    unsafe {
        check_status(SetEntriesInAclW(1, &entry, old.acl, &mut new))?;
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
        check_status(status)
    }
}

/// Enable SeRestorePrivilege for this process, which lets it make any account a file's owner.
fn enable_restore_privilege() -> io::Result<()> {
    let name: Vec<u16> = "SeRestorePrivilege\0".encode_utf16().collect();
    // SAFETY: the token handle is closed on every path; `name` is NUL-terminated.
    unsafe {
        let mut luid = LUID {
            LowPart: 0,
            HighPart: 0,
        };
        check_bool(LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid))?;
        let mut token: HANDLE = ptr::null_mut();
        check_bool(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES,
            &mut token,
        ))?;
        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let ok = AdjustTokenPrivileges(token, 0, &privileges, 0, ptr::null_mut(), ptr::null_mut());
        // Succeeds without enabling anything when the account doesn't hold the privilege.
        let last = GetLastError();
        CloseHandle(token);
        if ok == 0 {
            return Err(io::Error::from_raw_os_error(last as i32));
        }
        if last == ERROR_NOT_ALL_ASSIGNED {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "making another account the owner needs an elevated administrator",
            ));
        }
    }
    Ok(())
}

pub fn is_readable_by_others(path: &Path) -> io::Result<bool> {
    Ok(!Others::of(path)?.is_empty())
}

/// How to restrict `path` after [`is_readable_by_others`] said others can access it.
pub fn how_to_restrict(path: &Path) -> String {
    let account = current_user().map_or_else(
        |_| "<the account that runs watermelon>".to_owned(),
        |me| me.account_name(),
    );
    let shown = path.display();
    let mut advice = format!(
        "restrict it to {account} with `icacls \"{shown}\" /inheritance:r /grant:r \"{account}:F\"`"
    );
    let others = Others::of(path).unwrap_or_default();
    if let Some(owner) = &others.owner {
        advice = format!(
            "it is owned by {}; make {account} the owner with `icacls \"{shown}\" /setowner \"{account}\"`, then {advice}",
            owner.account_name()
        );
    }
    let explicit = others.explicit;
    if !explicit.is_empty() {
        let names: Vec<String> = explicit
            .iter()
            .map(|sid| format!("\"{}\"", sid.account_name()))
            .collect();
        advice += &format!(", then `icacls \"{shown}\" /remove {}`", names.join(" "));
    }
    advice
}

/// Who other than the trusted accounts can access a file or directory.
#[derive(Default)]
struct Others {
    /// No access list (everyone has full access), or an allow entry we don't parse.
    unknown: bool,
    /// Accounts with entries set on the file itself; `icacls /inheritance:r` leaves these.
    explicit: Vec<Sid>,
    /// Whether any access comes from an entry inherited from a parent.
    inherited: bool,
    /// An owner that isn't trusted: it can change the access list.
    owner: Option<Sid>,
}

impl Others {
    fn of(path: &Path) -> io::Result<Self> {
        let dacl = Dacl::of(path)?;
        let mut trusted = vec![
            current_user()?,
            well_known(WinLocalSystemSid)?,
            well_known(WinBuiltinAdministratorsSid)?,
            // Only appears in entries for new files and folders, and stands for whoever
            // creates them: that is us.
            well_known(WinCreatorOwnerSid)?,
        ];
        let mut others = Self::default();
        if !dacl.owner.is_null() {
            // SAFETY: a valid SID inside the descriptor `dacl` owns.
            let owner = unsafe { Sid::copy(dacl.owner)? };
            if owner.is_service() {
                trusted.push(owner);
            } else if !trusted.iter().any(|t| t.equals(owner.as_psid())) {
                others.owner = Some(owner);
            }
        }
        // An entry that applies only to what is created inside a directory doesn't grant
        // access to the directory itself, but it does to SQLite's -wal and -shm files.
        let is_dir = fs::metadata(path)?.is_dir();
        if dacl.acl.is_null() {
            others.unknown = true;
            return Ok(others);
        }
        // SAFETY: `dacl.acl` points at a valid ACL owned by `dacl`; GetAce only returns entries
        // inside it; every entry starts with an ACE_HEADER, and the simple allow types have
        // ACCESS_ALLOWED_ACE's layout with the SID (GetLengthSid bytes) at SidStart.
        unsafe {
            for i in 0..u32::from((*dacl.acl).AceCount) {
                let mut ace: *mut c_void = ptr::null_mut();
                if GetAce(dacl.acl, i, &mut ace) == 0 {
                    return Err(io::Error::last_os_error());
                }
                let header = &*ace.cast::<ACE_HEADER>();
                let ace_type = u32::from(header.AceType);
                let flags = u32::from(header.AceFlags);
                if !is_dir && flags & INHERIT_ONLY_ACE != 0 {
                    continue;
                }
                if OTHER_ALLOW_TYPES.contains(&ace_type) {
                    others.unknown = true;
                    continue;
                }
                if !SIMPLE_ALLOW_TYPES.contains(&ace_type) {
                    continue;
                }
                // Like the Unix check (mode & 0o077), any access at all counts.
                let mask = (*ace.cast::<ACCESS_ALLOWED_ACE>()).Mask;
                let sid: PSID = ace.byte_add(offset_of!(ACCESS_ALLOWED_ACE, SidStart));
                if mask == 0 || trusted.iter().any(|t| t.equals(sid)) {
                    continue;
                }
                if flags & INHERITED_ACE != 0 {
                    others.inherited = true;
                } else {
                    others.explicit.push(Sid::copy(sid)?);
                }
            }
        }
        Ok(others)
    }

    fn is_empty(&self) -> bool {
        !self.unknown && !self.inherited && self.explicit.is_empty() && self.owner.is_none()
    }
}

/// A security descriptor for new files or directories: protected, current user only.
struct PrivateSecurity {
    // Boxed so the pointer in `attributes` stays valid when this struct moves.
    _acl: Box<[u64]>,
    _descriptor: Box<SECURITY_DESCRIPTOR>,
    attributes: SECURITY_ATTRIBUTES,
}

impl PrivateSecurity {
    /// `pass_on_to_contents`: give files and folders created inside the same access.
    fn new(pass_on_to_contents: bool) -> io::Result<Self> {
        let mut acl = private_acl(&[&current_user()?], pass_on_to_contents)?;
        // SAFETY: SECURITY_DESCRIPTOR is plain data; Initialize… sets every field we rely on.
        let mut descriptor: Box<SECURITY_DESCRIPTOR> = Box::new(unsafe { std::mem::zeroed() });
        let sd: PSECURITY_DESCRIPTOR = (&raw mut *descriptor).cast();
        // SAFETY: `sd` points at the boxed descriptor; `acl` is a valid ACL kept alive in self.
        unsafe {
            check_bool(InitializeSecurityDescriptor(
                sd,
                SECURITY_DESCRIPTOR_REVISION,
            ))?;
            check_bool(SetSecurityDescriptorDacl(sd, 1, acl.as_mut_ptr().cast(), 0))?;
            check_bool(SetSecurityDescriptorControl(
                sd,
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            ))?;
        }
        Ok(Self {
            _acl: acl,
            _descriptor: descriptor,
            attributes: SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            },
        })
    }

    fn attributes(&mut self) -> *mut SECURITY_ATTRIBUTES {
        &raw mut self.attributes
    }
}

/// An access list that gives each of `users`, and no one else, full control.
fn private_acl(users: &[&Sid], pass_on_to_contents: bool) -> io::Result<Box<[u64]>> {
    let len = size_of::<ACL>()
        + users
            .iter()
            .map(|user| size_of::<ACCESS_ALLOWED_ACE>() + user.len())
            .sum::<usize>();
    let mut buf = vec![0u64; len.div_ceil(8)].into_boxed_slice();
    let acl: *mut ACL = buf.as_mut_ptr().cast();
    let flags = if pass_on_to_contents {
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
    } else {
        0
    };
    // SAFETY: `buf` is 8-byte aligned and `len` bytes long; every user is a valid SID.
    unsafe {
        check_bool(InitializeAcl(acl, len as u32, ACL_REVISION))?;
        for user in users {
            check_bool(AddAccessAllowedAceEx(
                acl,
                ACL_REVISION,
                flags,
                FILE_ALL_ACCESS,
                user.as_psid(),
            ))?;
        }
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
            check_bool(CopySid(len, buf.as_mut_ptr().cast(), sid))?;
            Ok(Self(buf))
        }
    }

    /// Look up an account by name, e.g. `NT SERVICE\watermelon`.
    fn of_account(name: &str) -> io::Result<Self> {
        let wide_name: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let mut sid = [0u32; (SECURITY_MAX_SID_SIZE as usize).div_ceil(4)];
        let mut sid_len = SECURITY_MAX_SID_SIZE;
        let mut domain = [0u16; 256];
        let mut domain_len = domain.len() as u32;
        let mut kind = 0;
        // SAFETY: the buffers and their lengths match; `wide_name` is NUL-terminated.
        let found = unsafe {
            LookupAccountNameW(
                ptr::null(),
                wide_name.as_ptr(),
                sid.as_mut_ptr().cast(),
                &mut sid_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut kind,
            )
        } != 0;
        if !found {
            let err = io::Error::last_os_error();
            return Err(io::Error::new(
                err.kind(),
                format!("looking up the account {name}: {err}"),
            ));
        }
        // SAFETY: LookupAccountNameW wrote a valid SID.
        unsafe { Self::copy(sid.as_mut_ptr().cast()) }
    }

    /// A Windows service's account (`NT SERVICE\…`): SID `S-1-5-80-…`.
    fn is_service(&self) -> bool {
        self.to_sid_string().starts_with("S-1-5-80-")
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

    /// `DOMAIN\name` as icacls accepts it, or `*S-1-…` when the account can't be looked up.
    fn account_name(&self) -> String {
        let mut name = [0u16; 256];
        let mut domain = [0u16; 256];
        let (mut name_len, mut domain_len) = (name.len() as u32, domain.len() as u32);
        let mut kind = 0;
        // SAFETY: the buffers and their lengths match; `self` is a valid SID.
        let found = unsafe {
            LookupAccountSidW(
                ptr::null(),
                self.as_psid(),
                name.as_mut_ptr(),
                &mut name_len,
                domain.as_mut_ptr(),
                &mut domain_len,
                &mut kind,
            )
        } != 0;
        if !found {
            return format!("*{}", self.to_sid_string());
        }
        let name = String::from_utf16_lossy(&name[..name_len as usize]);
        let domain = String::from_utf16_lossy(&domain[..domain_len as usize]);
        if domain.is_empty() {
            name
        } else {
            format!("{domain}\\{name}")
        }
    }

    fn to_sid_string(&self) -> String {
        let mut text: *mut u16 = ptr::null_mut();
        // SAFETY: `self` is a valid SID; on success `text` is a NUL-terminated string we free.
        unsafe {
            if ConvertSidToStringSidW(self.as_psid(), &mut text) == 0 {
                return "S-?".to_owned();
            }
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            let string = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text.cast());
            string
        }
    }
}

fn current_user() -> io::Result<Sid> {
    // SAFETY: the token handle is closed on every path; the buffer is sized by the first
    // GetTokenInformation call and 8-byte aligned for TOKEN_USER.
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        check_bool(OpenProcessToken(
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
        check_bool(CreateWellKnownSid(
            kind,
            ptr::null_mut(),
            buf.as_mut_ptr().cast(),
            &mut len,
        ))?;
        Sid::copy(buf.as_mut_ptr().cast())
    }
}

/// A file's access list and owner, with the security descriptor that holds them.
struct Dacl {
    acl: *mut ACL,
    owner: PSID,
    descriptor: PSECURITY_DESCRIPTOR,
}

impl Dacl {
    fn of(path: &Path) -> io::Result<Self> {
        let wide = wide(path);
        let mut dacl = Self {
            acl: ptr::null_mut(),
            owner: ptr::null_mut(),
            descriptor: ptr::null_mut(),
        };
        // SAFETY: `wide` is NUL-terminated; the descriptor is freed in Drop.
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
                &mut dacl.owner,
                ptr::null_mut(),
                &mut dacl.acl,
                ptr::null_mut(),
                &mut dacl.descriptor,
            )
        };
        check_status(status)?;
        Ok(dacl)
    }
}

impl Drop for Dacl {
    fn drop(&mut self) {
        // SAFETY: allocated by GetNamedSecurityInfoW (or null), freed once.
        unsafe { LocalFree(self.descriptor.cast()) };
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain([0]).collect()
}

/// For Win32 functions that return a BOOL and set the thread's last error.
fn check_bool(ok: impl Into<i32>) -> io::Result<()> {
    if ok.into() == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// For Win32 functions that return an error code (0 is success).
fn check_status(status: u32) -> io::Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(status as i32))
    }
}

#[cfg(test)]
pub mod testing {
    //! Give the local Users group access, the way `C:\ProgramData` does.

    use super::*;
    use windows_sys::Win32::Security::{SUB_CONTAINERS_AND_OBJECTS_INHERIT, WinBuiltinUsersSid};

    /// Let the local Users group read `path` (and, for a directory, what is created inside
    /// it), keeping the entries it already has.
    pub fn grant_users_read(path: &Path) {
        let inheritance = if path.is_dir() {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT
        } else {
            NO_INHERITANCE
        };
        grant_users(path, inheritance);
    }

    /// Let the local Users group read what is created inside `dir` from now on, but not
    /// `dir` itself.
    pub fn grant_users_read_to_new_items(dir: &Path) {
        grant_users(dir, SUB_CONTAINERS_AND_OBJECTS_INHERIT | INHERIT_ONLY_ACE);
    }

    /// `path`'s owner and the accounts its access list allows, as SID strings (`S-1-…`),
    /// sorted.
    pub fn owner_and_allowed(path: &Path) -> (String, Vec<String>) {
        let dacl = Dacl::of(path).unwrap();
        // SAFETY: valid SIDs and ACL inside the descriptor `dacl` owns; every entry starts
        // with an ACE_HEADER and allow entries have ACCESS_ALLOWED_ACE's layout.
        unsafe {
            let owner = Sid::copy(dacl.owner).unwrap().to_sid_string();
            let mut allowed = Vec::new();
            for i in 0..u32::from((*dacl.acl).AceCount) {
                let mut ace: *mut c_void = ptr::null_mut();
                check_bool(GetAce(dacl.acl, i, &mut ace)).unwrap();
                let header = &*ace.cast::<ACE_HEADER>();
                assert_eq!(u32::from(header.AceType), ACCESS_ALLOWED_ACE_TYPE);
                let sid: PSID = ace.byte_add(offset_of!(ACCESS_ALLOWED_ACE, SidStart));
                allowed.push(Sid::copy(sid).unwrap().to_sid_string());
            }
            allowed.sort();
            (owner, allowed)
        }
    }

    fn grant_users(path: &Path, inheritance: u32) {
        let users = well_known(WinBuiltinUsersSid).unwrap();
        add_allow_entry(path, &users, FILE_GENERIC_READ, inheritance).unwrap();
    }
}
