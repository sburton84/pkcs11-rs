#[cfg(test)]
mod test {
  use pkcs11_rs::context::*;

  describe! wrapper {
    it "can initialise a context" {
      let ctx = Context::new("/opt/nfast/toolkits/pkcs11/libcknfast.so");
    }

    describe! context {
      before_each {
        let ctx = Context::new("/opt/nfast/toolkits/pkcs11/libcknfast.so");
      }

      it "sdfsdfsd" {
        let ctx = Context::new("/opt/nfast/toolkits/pkcs11/libcknfast.so");
      }
    }
  }
}
