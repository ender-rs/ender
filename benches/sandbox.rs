use std::{fmt::Debug, hint::black_box, mem::MaybeUninit};

#[ignore]
#[divan::bench]
fn ufmt_format() {
    let mut string = String::new();
    ufmt::uwrite!(string, "qwerpoiuqweroiuasdfkljhzxcv,mbnqwerkha{}sdfpiuyzxcbkjhasdf,mn{}bqweriuzxcvkjhasdfm,nqbwerkljhzxvbcpoiuasdflkjqhwernmbzxcvjkasdfgkjqhwetlkqwerhjkw{}qeouiyhzbxcv", 1, 2, 3);
    black_box(&string);
}

#[ignore]
#[divan::bench]
fn std_format() {
    black_box(&format!("qwerpoiuqweroiuasdfkljhzxcv,mbnqwerkha{}sdfpiuyzxcbkjhasdf,mn{}bqweriuzxcvkjhasdfm,nqbwerkljhzxvbcpoiuasdflkjqhwernmbzxcvjkasdfgkjqhwetlkqwerhjkw{}qeouiyhzbxcv",1,2,3));
}
fn main() {
    divan::main()
}

#[divan::bench(args = [get_source_bytes()])]
fn benchmark_copy_from_slice_10_000_bytes(src: &Src) {
    #[allow(invalid_value)]
    let mut dst = unsafe { MaybeUninit::<[u8; 1_000]>::uninit().assume_init() };
    dst.copy_from_slice(src.0);
    black_box(&dst);
}

pub struct Src(&'static [u8; 1_000]);

impl Debug for Src {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Src").finish()
    }
}

fn get_source_bytes() -> Src {
    Src(&[100u8; 1_000])
}
