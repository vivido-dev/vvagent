//! Account-scoped storage protection. There is no network admission path: opening the
//! store or a credential requires the process account to own the filesystem object.
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Threading::*;

use agent_mesh_core::{ErrorCode, MeshError, Result};

fn io(error: std::io::Error) -> MeshError {
    MeshError::new(ErrorCode::Io, error.to_string())
}

fn refused() -> MeshError {
    MeshError::new(
        ErrorCode::NotAuthorized,
        "unsafe mesh object owner or reparse point",
    )
}

/// Check every existing component before creating directories or opening SQLite sidecars.
pub fn reject_reparse_points(path: &Path) -> Result<()> {
    let absolute = std::path::absolute(path).map_err(io)?;
    for component in absolute.ancestors() {
        match std::fs::symlink_metadata(component) {
            Ok(metadata) if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 => {
                return Err(refused());
            }
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(io(error)),
        }
    }
    Ok(())
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        // SAFETY: This pointer was allocated by a Windows security API with LocalAlloc.
        unsafe { LocalFree(self.0) };
    }
}

fn current_user() -> Result<Vec<usize>> {
    let mut raw = ptr::null_mut();
    // SAFETY: Current-process pseudo handle and writable output are valid.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io(std::io::Error::last_os_error()));
    }
    // SAFETY: OpenProcessToken returned an owned, non-null handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut length = 0;
    // SAFETY: The null-buffer call only reports the required size.
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            ptr::null_mut(),
            0,
            &mut length,
        )
    };
    if length == 0 || length > 65536 {
        return Err(refused());
    }
    let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
    // SAFETY: The aligned buffer is at least the size reported by Windows.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(io(std::io::Error::last_os_error()));
    }
    Ok(buffer)
}

/// Require the current SID as owner, then replace inherited access with one inheritable
/// full-control ACE for that SID. The handle never follows the final reparse point.
pub fn owner_only(path: &Path) -> Result<()> {
    reject_reparse_points(path)?;
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(io)?;
    let metadata = file.metadata().map_err(io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(refused());
    }
    let mut owner = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: File handle and all requested output pointers are valid.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io(std::io::Error::from_raw_os_error(status as i32)));
    }
    let _descriptor = LocalAllocation(descriptor);
    let user = current_user()?;
    // SAFETY: GetTokenInformation populated this aligned TOKEN_USER and its SID.
    let sid = unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    // SAFETY: Both SIDs are owned by live buffers returned by Windows.
    if owner.is_null() || unsafe { EqualSid(owner, sid) } == 0 {
        return Err(refused());
    }

    // Build an ACL directly from the validated SID; no names or command arguments carry it.
    // SAFETY: The SID remains valid throughout ACL construction.
    let sid_length = unsafe { GetLengthSid(sid) };
    let acl_length =
        size_of::<ACL>() + size_of::<ACCESS_ALLOWED_ACE>() - size_of::<u32>() + sid_length as usize;
    let mut storage = vec![0usize; acl_length.div_ceil(size_of::<usize>())];
    let acl = storage.as_mut_ptr().cast::<ACL>();
    // SAFETY: Storage is aligned and sized for the ACL and its single ACE.
    if unsafe { InitializeAcl(acl, acl_length as u32, ACL_REVISION) } == 0
        || unsafe {
            AddAccessAllowedAceEx(
                acl,
                ACL_REVISION,
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                FILE_ALL_ACCESS,
                sid,
            )
        } == 0
    {
        return Err(io(std::io::Error::last_os_error()));
    }
    // SAFETY: The file handle and ACL remain live; only the DACL is changed.
    let status = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(io(std::io::Error::from_raw_os_error(status as i32)));
    }
    Ok(())
}

/// A query handle detects process exit even while the process object still exists.
pub fn process_is_alive(pid: u32) -> bool {
    // SAFETY: OpenProcess accepts a numeric PID; no handle inheritance is requested.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return false;
    }
    let mut code = 0;
    // SAFETY: OpenProcess returned a live owned handle and code is writable.
    let alive = unsafe { GetExitCodeProcess(handle, &mut code) } != 0 && code == 259;
    // SAFETY: This is the single close for the owned process handle.
    unsafe { CloseHandle(handle) };
    alive
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;

    #[test]
    fn database_and_sidecars_have_a_protected_current_sid_dacl() {
        let directory =
            std::env::temp_dir().join(format!("mesh-acl-{}", agent_mesh_core::Opaque::generate()));
        let path = directory.join("mesh.sqlite");
        let store = Store::open(&path).unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let path = directory.join(format!("mesh.sqlite{suffix}"));
            let file = OpenOptions::new().read(true).open(path).unwrap();
            let mut owner = ptr::null_mut();
            let mut acl = ptr::null_mut();
            let mut descriptor = ptr::null_mut();
            // SAFETY: The live handle and requested output pointers are valid.
            assert_eq!(
                unsafe {
                    GetSecurityInfo(
                        file.as_raw_handle(),
                        SE_FILE_OBJECT,
                        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        &mut owner,
                        ptr::null_mut(),
                        &mut acl,
                        ptr::null_mut(),
                        &mut descriptor,
                    )
                },
                0
            );
            let _descriptor = LocalAllocation(descriptor);
            let user = current_user().unwrap();
            // SAFETY: Windows populated the aligned token buffer.
            let sid = unsafe { (*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid };
            // SAFETY: Descriptor and token allocation keep these SIDs live.
            assert_ne!(unsafe { EqualSid(owner, sid) }, 0);
            let mut control = 0;
            let mut revision = 0;
            // SAFETY: Descriptor is live and outputs are valid.
            assert_ne!(
                unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) },
                0
            );
            assert_ne!(control & SE_DACL_PROTECTED, 0);
            assert!(!acl.is_null());
            // SAFETY: A successful GetSecurityInfo returned a valid ACL.
            assert_eq!(unsafe { (*acl).AceCount }, 1);
            let mut ace = ptr::null_mut();
            // SAFETY: Index zero exists in the validated ACL.
            assert_ne!(unsafe { GetAce(acl, 0, &mut ace) }, 0);
            // SAFETY: Our owner-only ACL contains one ACCESS_ALLOWED_ACE.
            let ace = unsafe { &*(ace.cast::<ACCESS_ALLOWED_ACE>()) };
            assert_eq!(ace.Header.AceType, 0);
            assert_eq!(ace.Mask, FILE_ALL_ACCESS);
            // SAFETY: SidStart points to the variable-length SID in the live ACE.
            assert_ne!(
                unsafe { EqualSid((&ace.SidStart as *const u32).cast_mut().cast(), sid) },
                0
            );
        }
        drop(store);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_junction_in_a_state_or_runtime_path_is_rejected_before_creation() {
        let directory = std::env::temp_dir().join(format!(
            "mesh-junction-{}",
            agent_mesh_core::Opaque::generate()
        ));
        let target = directory.join("target");
        let link = directory.join("link");
        std::fs::create_dir_all(&target).unwrap();
        let status = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
        assert!(Store::open(link.join("state/mesh.sqlite")).is_err());
        assert!(reject_reparse_points(&link.join("tokens/new-token")).is_err());
        assert!(!target.join("state").exists());
        std::fs::remove_dir(&link).unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn process_liveness_distinguishes_a_running_and_exited_child() {
        assert!(process_is_alive(std::process::id()));
        let mut child = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "exit /b 0"])
            .spawn()
            .unwrap();
        child.wait().unwrap();
        assert!(!process_is_alive(child.id()));
        assert!(!process_is_alive(0));
    }
}
