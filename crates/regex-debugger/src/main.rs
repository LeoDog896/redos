use regex_full_syntax::as_ast;

fn main() {
    let regex = std::env::args().skip(1).collect::<Vec<_>>().join(" ");

    println!("{:?}", as_ast(&regex).unwrap());
}