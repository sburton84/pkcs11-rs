#![feature(plugin)]
#![plugin(clippy)]
#![cfg_attr(test, plugin(stainless))]

extern crate libloading;

pub mod cryptoki;

pub mod error;
pub mod pkcs11;