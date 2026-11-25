//! Combined device onboarding. The gateway never runs as root and cannot
//! execute arbitrary commands. An optional local, root-owned Unix socket
//! exposes just the existing administrator-approved peer enrollment operation.
use crate::broker::setup_key;

pub fn split_code(code: &str) -> Option<(&str, Option<&str>)> {
    if let Some(combined)=code.strip_prefix("DMW1:") {
        let (identity,peer)=combined.split_once(':')?;
        setup_key(identity)?;
        let bytes=peer.as_bytes();
        // 32 bytes in canonical padded base64: final data character has
        // two zero padding bits. Reject the all-zero public key.
        if bytes.len()!=44 || bytes[43]!=b'=' ||
            !bytes[..43].iter().all(|b|b.is_ascii_alphanumeric() || *b==b'+' || *b==b'/') ||
            !b"AEIMQUYcgkosw048".contains(&bytes[42]) ||
            bytes[..43].iter().all(|b|*b==b'A') {return None;}
        Some((identity,Some(peer)))
    } else {
        setup_key(code)?;
        Some((code,None))
    }
}

#[cfg(target_os="linux")]
pub fn enroll(identity:&str,peer:&str,host:&str)->Result<(),String> {
    enroll_at(std::path::Path::new("/run/desktop-mcp-enrollment.sock"),identity,peer,host)
}
#[cfg(not(target_os="linux"))]
pub fn enroll(_identity:&str,_peer:&str,_host:&str)->Result<(),String> {
    Err("DEVICE_PAIRED_WIREGUARD_HELPER_UNAVAILABLE_RETRY".into())
}

#[cfg(target_os="linux")]
fn enroll_at(path:&std::path::Path,identity:&str,peer:&str,host:&str)->Result<(),String> {
    use std::{io::{Read,Write},os::unix::net::UnixStream,time::Duration};
    let err=||"DEVICE_PAIRED_WIREGUARD_ENROLLMENT_FAILED_RETRY".to_string();
    let mut socket=UnixStream::connect(path).map_err(|_|err())?;
    // Authenticate the privileged socket endpoint, not just its filename.
    use std::os::fd::AsRawFd;
    let mut creds:libc::ucred=unsafe{std::mem::zeroed()};
    let mut len=std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe{libc::getsockopt(socket.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,
        &mut creds as *mut _ as *mut libc::c_void,&mut len)}!=0 ||
        len as usize!=std::mem::size_of::<libc::ucred>() || creds.uid!=0 {return Err(err());}
    socket.set_read_timeout(Some(Duration::from_secs(10))).map_err(|_|err())?;
    socket.set_write_timeout(Some(Duration::from_secs(2))).map_err(|_|err())?;
    socket.write_all(format!("{identity} {peer}\n").as_bytes()).map_err(|_|err())?;
    socket.shutdown(std::net::Shutdown::Write).map_err(|_|err())?;
    let mut reply=String::new();
    socket.take(256).read_to_string(&mut reply).map_err(|_|err())?;
    if reply==format!("OK {host}\n") {Ok(())}else{Err(err())}
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn combined_code_is_strict_and_preserves_legacy() {
        let identity=format!("DM1-{}",hex::encode(ed25519_dalek::SigningKey::from_bytes(&[42;32]).verifying_key().to_bytes()));
        let peer=format!("{}=","B".repeat(42)+"E");
        assert_eq!(split_code(&identity),Some((identity.as_str(),None)));
        let combined=format!("DMW1:{identity}:{peer}");
        assert_eq!(split_code(&combined),Some((identity.as_str(),Some(peer.as_str()))));
        for invalid in [format!("{combined}:extra"),format!("DMW1:{identity}:{}=","A".repeat(43)),
            format!("DMW1:{identity}:{}B=","A".repeat(42)),format!("DMW1:{identity}:{}","B".repeat(44)),
            format!("{combined}\n"),"DMW1:bad:bad".into()] {assert!(split_code(&invalid).is_none(),"{invalid}");}
    }
}
