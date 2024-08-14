use std::hint::black_box;

#[divan::bench]
fn ufmt_format() {
    let mut string = String::new();
    ufmt::uwrite!(string, "qwerpoiuqweroiuasdfkljhzxcv,mbnqwerkha{}sdfpiuyzxcbkjhasdf,mn{}bqweriuzxcvkjhasdfm,nqbwerkljhzxvbcpoiuasdflkjqhwernmbzxcvjkasdfgkjqhwetlkqwerhjkw{}qeouiyhzbxcv", 1, 2, 3);
    black_box(&string);
}

#[divan::bench]
fn std_format() {
    black_box(&format!("qwerpoiuqweroiuasdfkljhzxcv,mbnqwerkha{}sdfpiuyzxcbkjhasdf,mn{}bqweriuzxcvkjhasdfm,nqbwerkljhzxvbcpoiuasdflkjqhwernmbzxcvjkasdfgkjqhwetlkqwerhjkw{}qeouiyhzbxcv",1,2,3));
}
fn main() {
    divan::main()
}
