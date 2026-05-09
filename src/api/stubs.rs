//! Stub implementations for rarely-used GPGME operations.
//!
//! All functions here return either `not_impl()`, null, or a null pointer,
//! because the underlying operations are not required by the pacman use-case.

use core::ffi::{c_char, c_int, c_ulong};
use core::ptr;

use crate::context::GpgmeCtx;
use crate::data::GpgmeData;
use crate::error::not_impl;
use crate::ffi_types::GpgmeKey;

/// Macro for generating single-line stub functions with an attached doc string.
///
/// Variants:
/// - `ni!(doc, fn_name(args…) -> GpgmeError)` → returns `not_impl()`
/// - `ni!(doc, fn_name(args…) -> *mut u8)` → returns `ptr::null_mut()`
/// - `ni!(doc, fn_name(args…) -> *const c_char)` → returns `ptr::null()`
macro_rules! ni {
    ($doc:literal, $name:ident ($($arg:ident : $ty:ty),*) -> GpgmeError) => {
        #[doc = $doc]
        #[unsafe(no_mangle)]
        pub const unsafe extern "C" fn $name($($arg: $ty),*) -> u32 {
            $(let _ = $arg;)*
            not_impl()
        }
    };
    ($doc:literal, $name:ident ($($arg:ident : $ty:ty),*) -> *mut u8) => {
        #[doc = $doc]
        #[unsafe(no_mangle)]
        pub const unsafe extern "C" fn $name($($arg: $ty),*) -> *mut u8 {
            $(let _ = $arg;)*
            ptr::null_mut()
        }
    };
    ($doc:literal, $name:ident ($($arg:ident : $ty:ty),*) -> *const c_char) => {
        #[doc = $doc]
        #[unsafe(no_mangle)]
        pub const unsafe extern "C" fn $name($($arg: $ty),*) -> *const c_char {
            $(let _ = $arg;)*
            ptr::null()
        }
    };
}

// ── Key-management stubs ───────────────────────────────────────────────────────

ni!("Not implemented: create a subkey.", gpgme_op_createsubkey(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,algo:*const c_char,reserved:c_ulong,expire:c_ulong,flags:u32) -> GpgmeError);
ni!("Not implemented: create a subkey (async).", gpgme_op_createsubkey_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,algo:*const c_char,reserved:c_ulong,expire:c_ulong,flags:u32) -> GpgmeError);
ni!("Not implemented: add a user ID.", gpgme_op_adduid(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,uid:*const c_char,flags:u32) -> GpgmeError);
ni!("Not implemented: add a user ID (async).", gpgme_op_adduid_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,uid:*const c_char,flags:u32) -> GpgmeError);
ni!("Not implemented: revoke a user ID.", gpgme_op_revuid(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,uid:*const c_char,flags:u32) -> GpgmeError);
ni!("Not implemented: revoke a user ID (async).", gpgme_op_revuid_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,uid:*const c_char,flags:u32) -> GpgmeError);
ni!("Not implemented: revoke a signature.", gpgme_op_revsig(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,signing_key:*mut GpgmeKey,uid:*const c_char,flags:u32) -> GpgmeError);
ni!("Not implemented: revoke a signature (async).", gpgme_op_revsig_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,signing_key:*mut GpgmeKey,uid:*const c_char,flags:u32) -> GpgmeError);
ni!("Not implemented: set a UID flag.", gpgme_op_set_uid_flag(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,uid:*const c_char,name:*const c_char,value:*const c_char) -> GpgmeError);
ni!("Not implemented: set a UID flag (async).", gpgme_op_set_uid_flag_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,uid:*const c_char,name:*const c_char,value:*const c_char) -> GpgmeError);
ni!("Not implemented: set key expiry.", gpgme_op_setexpire(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,expire:c_ulong,subfprs:*const c_char,flags:u32) -> GpgmeError);
ni!("Not implemented: set key expiry (async).", gpgme_op_setexpire_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,expire:c_ulong,subfprs:*const c_char,flags:u32) -> GpgmeError);
ni!("Not implemented: set owner trust.", gpgme_op_setownertrust(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,value:*const c_char) -> GpgmeError);
ni!("Not implemented: set owner trust (async).", gpgme_op_setownertrust_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,value:*const c_char) -> GpgmeError);
ni!("Not implemented: sign a key.", gpgme_op_keysign(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,uid:*const c_char,expire:c_ulong,flags:u32) -> GpgmeError);
ni!("Not implemented: sign a key (async).", gpgme_op_keysign_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,uid:*const c_char,expire:c_ulong,flags:u32) -> GpgmeError);
ni!("Not implemented: set TOFU policy.", gpgme_op_tofu_policy(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,policy:u32) -> GpgmeError);
ni!("Not implemented: set TOFU policy (async).", gpgme_op_tofu_policy_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,policy:u32) -> GpgmeError);
ni!("Not implemented: change passphrase.", gpgme_op_passwd(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,flags:u32) -> GpgmeError);
ni!("Not implemented: change passphrase (async).", gpgme_op_passwd_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,flags:u32) -> GpgmeError);
ni!("Not implemented: delete a key.", gpgme_op_delete(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,allow_secret:c_int) -> GpgmeError);
ni!("Not implemented: delete a key (async).", gpgme_op_delete_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,allow_secret:c_int) -> GpgmeError);
ni!("Not implemented: extended delete.", gpgme_op_delete_ext(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,flags:u32) -> GpgmeError);
ni!("Not implemented: extended delete (async).", gpgme_op_delete_ext_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,flags:u32) -> GpgmeError);

// ── Interactive / card / assuan stubs ─────────────────────────────────────────

ni!("Not implemented: interactive key editing.", gpgme_op_edit(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,cb:*mut u8,cb_value:*mut u8,out:*mut GpgmeData) -> GpgmeError);
ni!("Not implemented: interactive key editing (async).", gpgme_op_edit_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,cb:*mut u8,cb_value:*mut u8,out:*mut GpgmeData) -> GpgmeError);
ni!("Not implemented: card editing.", gpgme_op_card_edit(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,cb:*mut u8,cb_value:*mut u8,out:*mut GpgmeData) -> GpgmeError);
ni!("Not implemented: card editing (async).", gpgme_op_card_edit_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,cb:*mut u8,cb_value:*mut u8,out:*mut GpgmeData) -> GpgmeError);
ni!("Not implemented: key interaction.", gpgme_op_interact(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,flags:u32,fnc:*mut u8,fnc_value:*mut u8,out:*mut GpgmeData) -> GpgmeError);
ni!("Not implemented: key interaction (async).", gpgme_op_interact_start(ctx:*mut GpgmeCtx,key:*mut GpgmeKey,flags:u32,fnc:*mut u8,fnc_value:*mut u8,out:*mut GpgmeData) -> GpgmeError);
ni!("Not implemented: spawn a child process.", gpgme_op_spawn(ctx:*mut GpgmeCtx,file:*const c_char,argv:*mut*const c_char,datain:*mut GpgmeData,dataout:*mut GpgmeData,dataerr:*mut GpgmeData,flags:u32) -> GpgmeError);
ni!("Not implemented: spawn a child process (async).", gpgme_op_spawn_start(ctx:*mut GpgmeCtx,file:*const c_char,argv:*mut*const c_char,datain:*mut GpgmeData,dataout:*mut GpgmeData,dataerr:*mut GpgmeData,flags:u32) -> GpgmeError);
ni!("Not implemented: Assuan transaction.", gpgme_op_assuan_transact(ctx:*mut GpgmeCtx,cmd:*const c_char,data_cb:*mut u8,data_cb_val:*mut u8,inq_cb:*mut u8,inq_cb_val:*mut u8,stat_cb:*mut u8,stat_cb_val:*mut u8) -> GpgmeError);
ni!("Not implemented: Assuan transaction (async).", gpgme_op_assuan_transact_start(ctx:*mut GpgmeCtx,cmd:*const c_char,data_cb:*mut u8,data_cb_val:*mut u8,inq_cb:*mut u8,inq_cb_val:*mut u8,stat_cb:*mut u8,stat_cb_val:*mut u8) -> GpgmeError);
ni!("Not implemented: extended Assuan transaction.", gpgme_op_assuan_transact_ext(ctx:*mut GpgmeCtx,cmd:*const c_char,data_cb:*mut u8,data_cb_val:*mut u8,inq_cb:*mut u8,inq_cb_val:*mut u8,stat_cb:*mut u8,stat_cb_val:*mut u8,op_err:*mut u32) -> GpgmeError);
ni!("Not implemented: retrieve Assuan result.", gpgme_op_assuan_result(ctx:*mut GpgmeCtx) -> *mut u8);

// ── Config stubs ──────────────────────────────────────────────────────────────

ni!("Not implemented: load config.", gpgme_op_conf_load(ctx:*mut GpgmeCtx,r_conf:*mut *mut u8) -> GpgmeError);
ni!("Not implemented: save config.", gpgme_op_conf_save(ctx:*mut GpgmeCtx,conf:*mut u8) -> GpgmeError);
ni!("Not implemented: retrieve config directory.", gpgme_op_conf_dir(ctx:*mut GpgmeCtx,comp:*const c_char,r_dir:*mut*mut c_char) -> GpgmeError);

// ── Audit / trust / VFS / swdb stubs ─────────────────────────────────────────

ni!("Not implemented: retrieve audit log.", gpgme_op_getauditlog(ctx:*mut GpgmeCtx,output:*mut GpgmeData,flags:u32) -> GpgmeError);
ni!("Not implemented: retrieve audit log (async).", gpgme_op_getauditlog_start(ctx:*mut GpgmeCtx,output:*mut GpgmeData,flags:u32) -> GpgmeError);
ni!("Not implemented: start trust-list enumeration.", gpgme_op_trustlist_start(ctx:*mut GpgmeCtx,pattern:*const c_char,max_level:c_int) -> GpgmeError);
ni!("Not implemented: next trust-list entry.", gpgme_op_trustlist_next(ctx:*mut GpgmeCtx,r_item:*mut *mut u8) -> GpgmeError);
ni!("Not implemented: end trust-list enumeration.", gpgme_op_trustlist_end(ctx:*mut GpgmeCtx) -> GpgmeError);
ni!("Not implemented: mount a VFS.", gpgme_op_vfs_mount(ctx:*mut GpgmeCtx,container_file:*const c_char,mount_dir:*const c_char,flags:u32,op_err:*mut u32) -> GpgmeError);
ni!("Not implemented: create a VFS container.", gpgme_op_vfs_create(ctx:*mut GpgmeCtx,recipients:*mut*mut GpgmeKey,container_file:*const c_char,flags:u32,op_err:*mut u32) -> GpgmeError);
ni!("Not implemented: VFS mount result.", gpgme_op_vfs_mount_result(ctx:*mut GpgmeCtx) -> *mut u8);
ni!("Not implemented: query software database.", gpgme_op_query_swdb(ctx:*mut GpgmeCtx,name:*const c_char,iversion:*const c_char,flags:u32) -> GpgmeError);
ni!("Not implemented: software database query result.", gpgme_op_query_swdb_result(ctx:*mut GpgmeCtx) -> *mut u8);

// ── Key server / random stubs ─────────────────────────────────────────────────

ni!("Not implemented: receive keys from a key server.", gpgme_op_receive_keys(ctx:*mut GpgmeCtx,keyids:*mut*const c_char) -> GpgmeError);
ni!("Not implemented: receive keys from a key server (async).", gpgme_op_receive_keys_start(ctx:*mut GpgmeCtx,keyids:*mut*const c_char) -> GpgmeError);
ni!("Not implemented: generate random bytes.", gpgme_op_random_bytes(ctx:*mut GpgmeCtx,buf:*mut u8,length:usize) -> GpgmeError);
ni!("Not implemented: generate a random value.", gpgme_op_random_value(ctx:*mut GpgmeCtx,nbytes:usize) -> *mut u8);
