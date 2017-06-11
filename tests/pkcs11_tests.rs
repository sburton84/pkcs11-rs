#![feature(plugin)]
#![plugin(stainless)]

extern crate pkcs11_rs;

#[cfg(test)]
mod test {
  use pkcs11_rs::pkcs11::*;

  describe! wrapper {
    it "can initialise a context" {
      let p11 = Pkcs11::new("/usr/lib/opencryptoki/libopencryptoki.so").expect("Error initialising Pkcs11");
    }

    describe! pkcs11 {
      before_each {
        let p11 = Pkcs11::new("/usr/lib/opencryptoki/libopencryptoki.so").expect("Error initialising Pkcs11");
      }

      it "can get slot list" {
        let slots = p11.get_slot_list(true);
      }

      // it "can iterate over slots" {
      //   let slots = p11.get_slot_list(true);

      //   for slot in slots {
          
      //   }
      // }
    }
  }
}
