mod error;
mod registry;
mod init;
mod slot;

use std::sync::Mutex;
use std::sync::Arc;

use libloading::Library;

use cryptoki::CK_FUNCTION_LIST;
use pkcs11::error::*;
use pkcs11::registry::get_entry;

pub struct Pkcs11 {
  lib: Library,
  function_list: CK_FUNCTION_LIST,
  initialized: Mutex<bool>
}

impl Drop for Pkcs11 {
  fn drop(&mut self) {
    self.finalize();
  }
}

impl Pkcs11 {
  pub fn new(lib_path: &str) -> Result<Arc<Pkcs11>> {
    Ok(try!(get_entry(lib_path)))
  }
}
