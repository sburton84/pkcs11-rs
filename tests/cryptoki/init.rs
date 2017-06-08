#[cfg(test)]
mod test {
  use libloading;
  use std::ptr;
  use pkcs11_rs::funclist::*;

  describe! cryptoki {
    before_each {
      let lib = load_lib("/opt/nfast/toolkits/pkcs11/libcknfast.so");
      let function_list = get_function_list(&lib);
    }

    it "can call C_Initialize" {
      unsafe {
        (function_list.C_Initialize).unwrap()(ptr::null_mut());
      }
    }
  }
}
