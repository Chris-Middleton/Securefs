mod types;
mod cipher;
mod file;

use std::fmt::Formatter;
use std::fs::{File, OpenOptions};
use std::io::{Error, ErrorKind, Read, Seek, SeekFrom, Write};
use bcrypt::{BcryptError, BcryptResult};
use crate::file::SfsFile;
use crate::types::SfsErrorKind;

fn make_demo_files(){
    let mut f1 = File::create("demo1.txt").unwrap();
    let mut f2 = File::create("demo2.txt").unwrap();
    f1.write(b"Hello, this is a demo of the encrypted filesystem project.\n").unwrap();
    f2.write(b"This is the second file.\n").unwrap();
    let mut zeros = [b'0'; 100];
    zeros[99] = b'\n';
    for _ in 0..100{
        f2.write(&zeros);
    }
}


fn demo_instruction(args: &str){
    println!("> {}", args);
    let args = args
        .split(' ')
        .map(|word|String::from(word))
        .collect::<Vec<_>>();
    if let Err(error) = run(args){
        println!("{}", error)
    }
}
fn demo(){
    make_demo_files();
    demo_instruction("-write demo.sfs demo1 demo1.txt");
    demo_instruction("-write demo.sfs copy demo1.txt");
    demo_instruction("-write demo.sfs demo2 demo2.txt");
    demo_instruction("-list demo.sfs");
    demo_instruction("-read demo.sfs copy");
    demo_instruction("-read demo.sfs demo2");
    println!("Flipping a single bit in demo.sfs");
    flip_bit("demo.sfs", 40);
    demo_instruction("-read demo.sfs demo2");

    //demo_instruction("-open demo.sfs");
}

fn flip_bit(filename: &str, offset_from_end: i64){
    let mut f = OpenOptions::new()
        .write(true)
        .read(true)
        .open(filename)
        .unwrap();
    f.seek(SeekFrom::End(-offset_from_end)).unwrap();
    let mut buf = [0u8; 1];
    f.read(&mut buf).unwrap();
    f.seek(SeekFrom::Current(-1)).unwrap();
    buf[0] ^= 0b1;
    f.write(&buf).unwrap();
}

fn main() {
    //();
    let mut args = std::env::args().fuse();
    args.next();
    let args = args.collect::<Vec<_>>();
    //let args = vec!["-open".into(), "save.sfs".into()];
    if let Err(error) = run(args){
        println!("{}", error)
    }
}

fn run(args: Vec<String>) -> Result<(), SfsErrorKind>{
    if args.len() < 2{
        return Err(SfsErrorKind::BadUsage)
    }
    match args[0].as_str() {
        "-list" | "-l" if args.len() == 2 => {
            SfsFile::open_or_create(args[1].as_str(), get_password)?
                .list(std::io::stdout())
        }
        "-read" | "-r" if args.len() == 3 => {
            SfsFile::open_or_create(args[1].as_str(), get_password)?
                .read(args[2].as_str(), std::io::stdout())
        }
        "-write" | "-w" if args.len() == 4 => {
            let data = File::open(args[3].as_str())
                .map_err(|_| SfsErrorKind::IoError)?;
            SfsFile::open_or_create(args[1].as_str(), get_password)?
                .write(args[2].as_str(), data)
        }
        "-open" | "-o" if args.len() == 2 => {
            let mut file = SfsFile::open_or_create(args[1].as_str(), get_password)?;
            loop{
                let input = get_input()?;
                let input = input.trim();
                if input.eq("list"){
                    file.list(std::io::stdout())?;
                    continue;
                }
                if let Some((command, data)) = input.split_once(' '){
                    if command.eq("read"){
                        file.read(data, std::io::stdout())?;
                        continue;
                    }
                    if command.eq("write"){
                        if let Some((id, data)) = data.split_once(' '){
                            let data = File::open(data)
                                .map_err(|_|SfsErrorKind::IoError)?;
                            file.write(id, data)?;
                            continue;
                        }
                    }
                }
                return Err(SfsErrorKind::BadUsage);
            }
        }
        _ => Err(SfsErrorKind::BadUsage)
    }
}

fn get_password() -> String{
    write!(std::io::stderr(), "Please enter your Password: ");
    std::io::stderr().flush();
    let mut password = String::new();
    std::io::stdin().read_line(&mut password).unwrap();

    password
}

fn get_input() -> Result<String, SfsErrorKind>{
    print!("Please enter list, read [id], or write [id] [file]: ");
    std::io::stdout().flush();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).map_err(|e|SfsErrorKind::IoError)?;
    return Ok(input)
}

impl std::fmt::Display for SfsErrorKind{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self{
            SfsErrorKind::CorruptedFile =>
                writeln!(f, "The encrypted file is corrupted, it was likely tampered with by a bad actor."),
            SfsErrorKind::IoError =>
                writeln!(f, "An unexpected IO Error occurred."),
            SfsErrorKind::CantWrite =>
                writeln!(f, "The output cannot be written to the requested buffer - it might be full."),
            SfsErrorKind::CantOpenFile =>
                writeln!(f, "Unable to open the requested file."),
            SfsErrorKind::NotPresent =>
                writeln!(f, "The binding you are trying to read from is not present."),
            SfsErrorKind::AlreadyPresent =>
                writeln!(f, "The binding you are trying to use already exists."),
            SfsErrorKind::BadUsage => {
                writeln!(f, "+------------------------------------+")?;
                writeln!(f, "| Chris's Secure File System Project |")?;
                writeln!(f, "| CSC 321                            |")?;
                writeln!(f, "+------------------------------------+")?;
                writeln!(f, "Usage:")?;
                writeln!(f, "  sfs -help")?;
                writeln!(f, "    Display this help window")?;
                writeln!(f, "  sfs -list [filename]")?;
                writeln!(f, "    Lists the names of entries in the file")?;
                writeln!(f, "  sfs -read [filename] [id]")?;
                writeln!(f, "    Displays the entry mapped to id")?;
                writeln!(f, "  sfs -write [filename] [id] [path]")?;
                writeln!(f, "    Binds id to an encrypted copy of the file at path.")?;
                writeln!(f, "  sfs -open [filename]")?;
                writeln!(f, "    Opens a file for interactive usage.")
            }
            SfsErrorKind::IncorrectPassword =>
                writeln!(f, "The password you entered was incorrect."),
        }
    }
}