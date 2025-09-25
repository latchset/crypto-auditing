// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Keylime Authors

use anyhow::{Result, anyhow};
use std::ffi::CString;
use std::io::Error;

pub fn run_as(user: &str, group: &str) -> Result<()> {
    let group = CString::new(group.as_bytes())?;
    let mut grp = unsafe { std::mem::zeroed::<libc::group>() };
    let mut grpbuf = vec![0; 4096];
    let mut grpent = std::ptr::null_mut::<libc::group>();

    if unsafe {
        libc::getgrnam_r(
            group.as_ptr(),
            &mut grp,
            grpbuf.as_mut_ptr(),
            grpbuf.len(),
            &mut grpent,
        )
    } != 0
    {
        return Err(Error::last_os_error().into());
    }

    let user = CString::new(user.as_bytes())?;
    let mut pwd = unsafe { std::mem::zeroed::<libc::passwd>() };
    let mut pwdbuf = vec![0; 4096];
    let mut pwdent = std::ptr::null_mut::<libc::passwd>();

    if unsafe {
        libc::getpwnam_r(
            user.as_ptr(),
            &mut pwd,
            pwdbuf.as_mut_ptr(),
            pwdbuf.len(),
            &mut pwdent,
        )
    } != 0
    {
        return Err(Error::last_os_error().into());
    }

    if unsafe { libc::setgid(grp.gr_gid) } != 0 {
        return Err(Error::last_os_error().into());
    }

    // Get list of supplementary groups
    let mut groups = vec![0; 32];
    let mut ngroups: i32 = groups.len().try_into().unwrap();
    if unsafe { libc::getgrouplist(pwd.pw_name, grp.gr_gid, groups.as_mut_ptr(), &mut ngroups) } < 0
    {
        // Allocate a Vec and try again
        groups.reserve_exact(ngroups as usize - groups.len());
        ngroups = groups.len().try_into().unwrap();
        if unsafe { libc::getgrouplist(pwd.pw_name, grp.gr_gid, groups.as_mut_ptr(), &mut ngroups) }
            < 0
        {
            return Err(anyhow!("Could not get list of supplementary groups"));
        }
    }

    // Set supplementary groups
    if unsafe { libc::setgroups(ngroups as usize, groups.as_ptr()) } != 0 {
        return Err(Error::last_os_error().into());
    }

    // Set uid
    if unsafe { libc::setuid(pwd.pw_uid) } != 0 {
        return Err(Error::last_os_error().into());
    }

    Ok(())
}
