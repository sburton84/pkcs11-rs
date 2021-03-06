#![feature(plugin)]
#![plugin(stainless)]

extern crate pkcs11_rs;

#[cfg(test)]
mod test {
  use pkcs11_rs::pkcs11::*;

  describe! wrapper {
    it "can initialise a context" {
      let p11 = Pkcs11::new("/usr/lib/libsofthsm2.so").expect("Error initialising Pkcs11");
    }

    describe! pkcs11 {
      before_each {
        let p11 = Pkcs11::new("/opt/nfast/toolkits/pkcs11/libcknfast.so").expect("Error initialising Pkcs11");
      }

      it "can get slot list" {
        let slots = p11.get_slot_list(false).expect("Error getting slot list");
      }

      it "can iterate over slots and get slot info" {
        let mut slots = p11.get_slot_list(false).expect("Error getting slot list");

        for mut slot in slots {
          let slot_info = slot.get_slot_info().expect("Error getting slot info");
        }
      }

      describe! slot {
        before_each {
          let slots = p11.get_slot_list(false).expect("Error getting slot list");
          let slot = &slots[0];
        }

        it "can open session" {
          let session = slot.open_session().expect("Error opening session");
        }

        it "can log in and out of session" {
          let session = slot.open_session().expect("Error opening session");
          session.log_in("1234").expect("Error logging in");
          session.log_out().expect("Error logging out");
        }

        describe! session {
          before_each {
            let session = slot.open_session().expect("Error opening session");
            session.log_in("1234").expect("Error logging in");
          }

          it "can get objects" {
            let mut attributes = [Attribute::Label("pkcsrsa")];
            let objects = session.find_objects(&attributes).expect("Error finding objects");
          }

          it "can generate a key" {
            let mut attributes = [Attribute::Label("des3key")];
            let key = session.generate_key(Mechanism::Des3KeyGen, &attributes).expect("Error generating key");
          }

          describe! key {
            before_each {
              let mut attributes = [Attribute::Label("des3key"), Attribute::Encrypt(true)];
              let key = session.generate_key(Mechanism::Des3KeyGen, &attributes).expect("Error generating key");
            }

            it "can encrypt and decrypt some data" {
              let mut cipher = key.encrypt(Mechanism::Des3Ecb, &mut "TestData".to_string().into_bytes()).expect("Error performing encrypt");
              let plain_bytes = key.decrypt(Mechanism::Des3Ecb, &mut cipher).expect("Error performing decrypt");
              let plain = String::from_utf8(plain_bytes).unwrap();

              assert_eq!(plain, "TestData");
            }
          }
        }
      }
    }
  }
}
