//! Key-generation using Sequoia-PGP, imported into the local GnuPG keyring.

use core::time::Duration;
use std::io::{self, Write as _};
use std::process::{Command, Stdio};

use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::serialize::Serialize as _;

/// Generate a new `OpenPGP` certificate for `userid` and import it via `gpg-sq`.
///
/// When `expire_secs` is greater than zero the primary key and subkeys are
/// given a validity period of that many seconds.
pub fn genkey_sq(home: &str, userid: &str, expire_secs: u64) -> sequoia_openpgp::Result<()> {
    let mut builder = CertBuilder::new()
        .add_userid(userid)
        .add_signing_subkey()
        .add_transport_encryption_subkey();
    if expire_secs > 0 {
        builder = builder.set_validity_period(Some(Duration::from_secs(expire_secs)));
    }
    let (cert, _rev) = match builder.generate() {
        Ok(val) => val,
        Err(err) => return Err(err),
    };
    let mut key_bytes = Vec::new();
    if let Err(err) = cert.as_tsk().serialize(&mut key_bytes) {
        return Err(err);
    }

    drop(
        Command::new("/usr/bin/gpg-sq")
            .args(["--homedir", home, "--batch", "--no-tty", "--import"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .and_then(|mut child| {
                let mut stdin = match child
                    .stdin
                    .take()
                    .ok_or_else(|| io::Error::other("stdin not piped"))
                {
                    Ok(val) => val,
                    Err(err) => return Err(err),
                };
                match stdin.write_all(&key_bytes) {
                    Ok(()) => (),
                    Err(err) => return Err(err),
                }
                child.wait()
            }),
    );
    Ok(())
}
