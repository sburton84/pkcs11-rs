#![feature(plugin)]
#![plugin(stainless)]

extern crate pkcs11_rs;
extern crate libloading;
extern crate libc;

#[cfg(test)]
mod test {
  use libc;
  use std::ptr;
  use libloading;
  use pkcs11_rs::cryptoki::*;

  describe! cryptoki {
    it "can get function list" {
      let lib = libloading::Library::new("/opt/nfast/toolkits/pkcs11/libcknfast.so").expect("Error loading PKCS#11 library");

      let mut function_list: CK_FUNCTION_LIST_PTR = ptr::null_mut();

      unsafe {
        let get_function_list: libloading::Symbol<unsafe extern fn(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV> = lib.get(b"C_GetFunctionList").expect("Error getting C_GetFunctionList function pointer");
        get_function_list(&mut function_list as CK_FUNCTION_LIST_PTR_PTR);
      }
    }

    it "can get C_Initialize from function list" {
      let lib = libloading::Library::new("/opt/nfast/toolkits/pkcs11/libcknfast.so").expect("Error loading PKCS#11 library");

      let function_list: CK_FUNCTION_LIST;

      unsafe {
        let mut function_list_ptr: CK_FUNCTION_LIST_PTR = ptr::null_mut();

        let get_function_list: libloading::Symbol<unsafe extern fn(ppFunctionList: CK_FUNCTION_LIST_PTR_PTR) -> CK_RV> = lib.get(b"C_GetFunctionList").expect("Error getting C_GetFunctionList function pointer");
        get_function_list(&mut function_list_ptr as CK_FUNCTION_LIST_PTR_PTR);

        function_list = *function_list_ptr;
      }

      // Assert that function point is non-null
      assert!(function_list.C_Initialize.unwrap() as *const libc::c_void != ptr::null() as *const libc::c_void);
    }
  }
}
