#[cfg(test)]
mod test {
  use libc;
  use std::ptr;
  use pkcs11_rs::funclist::*;

  describe! cryptoki {
    it "can get function list" {
      let function_list = get_function_list(&load_lib("/opt/nfast/toolkits/pkcs11/libcknfast.so"));
    }

    it "can get C_Initialize from function list" {
      let function_list = get_function_list(&load_lib("/opt/nfast/toolkits/pkcs11/libcknfast.so"));

      // Assert that function point is non-null
      assert!(function_list.C_Initialize.unwrap() as *const libc::c_void != ptr::null() as *const libc::c_void);
    }
  }
}
