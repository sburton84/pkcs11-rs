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
        let p11 = Pkcs11::new("/usr/lib/libsofthsm2.so").expect("Error initialising Pkcs11");
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
            let objects = session.find_objects(&mut attributes).expect("Error finding objects");
          }
        }
      }
    }
  }
}
