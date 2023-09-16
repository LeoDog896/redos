use regex_full_syntax::parse;

fn main() {
    let regex = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    let regex = parse(&regex).unwrap();

    println!("{:#?}", regex);

    println!("{}", regex);
}
