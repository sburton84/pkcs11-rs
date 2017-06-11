#![feature(plugin)]
#![plugin(clippy)]
#![cfg_attr(test, plugin(stainless))]

extern crate libloading;

#[macro_use]
extern crate lazy_static;

pub mod pkcs11;