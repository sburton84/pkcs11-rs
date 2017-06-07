#![feature(plugin)]
#![plugin(stainless)]

extern crate pkcs11_rs;
extern crate libloading;

#[cfg(test)]
mod test {
  use libloading;
  use std::ptr;
  use pkcs11_rs::cryptoki::*;

  describe! cryptoki {
    before_each {
      let lib = libloading::Library::new("/opt/nfast/toolkits/pkcs11/libcknfast.so").expect("Error loading PKCS#11 library");
      unsafe {
        let func: libloading::Symbol<unsafe extern fn(CK_VOID_PTR) -> CK_RV> = lib.get(b"C_Initialize").expect("Error getting function");
        func(ptr::null_mut());
      }
    }


    it "can call C_Initialize" {

      let lib = libloading::Library::new("/opt/nfast/toolkits/pkcs11/libcknfast.so").expect("Error loading PKCS#11 library");
      unsafe {
        let func: libloading::Symbol<unsafe extern fn(CK_VOID_PTR) -> CK_RV> = lib.get(b"C_Initialize").expect("Error getting C_Initialize function pointer");
        func(ptr::null_mut());
      }
    }
  }
}
