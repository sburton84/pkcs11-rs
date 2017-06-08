#![feature(plugin)]
#![plugin(stainless)]

extern crate pkcs11_rs;

#[cfg(test)]
mod test {
  use pkcs11_rs::pkcs11::*;

  describe! wrapper {
    it "can initialise a context" {
      let ctx = Pkcs11::new("/opt/nfast/toolkits/pkcs11/libcknfast.so");
    }

    describe! pkcs11 {
      before_each {
        let ctx = Pkcs11::new("/opt/nfast/toolkits/pkcs11/libcknfast.so");
      }
    }
  }
}
