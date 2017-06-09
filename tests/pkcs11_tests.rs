#![feature(plugin)]
#![plugin(stainless)]

extern crate pkcs11_rs;

#[cfg(test)]
mod test {
  use pkcs11_rs::pkcs11::*;

  describe! wrapper {
    it "can initialise a context" {
      let p11 = Pkcs11::new("/opt/nfast/toolkits/pkcs11/libcknfast.so").expect("Error initialising Pkcs11");
    }

    describe! pkcs11 {
      before_each {
        let p11 = Pkcs11::new("/opt/nfast/toolkits/pkcs11/libcknfast.so").expect("Error initialising Pkcs11");
      }

      it "can get slot list" {
        let slots = p11.lock().unwrap().get_slot_list(true);
      }
    }
  }
}
