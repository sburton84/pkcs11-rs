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
        let slots = p11.get_slot_list(false);
      }

      it "can iterate over slots and get slot info" {
        let mut slots = p11.get_slot_list(false).unwrap();

        for mut slot in slots {
          let slot_info = slot.get_slot_info();
        }
      }
    }
  }
}
