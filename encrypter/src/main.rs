#![deny(warnings, clippy::pedantic, clippy::all, rust_2018_idioms)]

#[derive(clap::Clap, Debug)]
#[clap(name = "Encrypter", version)]
struct Args {
    /// Print the output as raw bytes.
    /// By default, the output will be base64 encoded
    #[clap(short, long)]
    raw: bool,

    /// Decode the secret with base64
    #[clap(short, long)]
    base64_secret: bool,

    /// Secret to be used for encryption
    #[clap(short, long, env = "ENCRYPTER_SECRET")]
    secret: Option<String>,

    /// Delimiter for joining the payload.
    /// Default value is \0
    #[clap(short, long)]
    delimiter: Option<String>,

    payload: Vec<String>,
}

fn main() {
    use clap::Clap;
    let args = Args::parse();

    if args.payload.is_empty() {
        eprintln!("Nothing to encrypt");
        std::process::exit(-1);
    }

    let secret = match args.secret {
        Some(secret) => {
            if args.base64_secret {
                base64::decode(secret).unwrap_or_else(|_| {
                    eprintln!("Invalid base64 secret");
                    std::process::exit(-1);
                })
            } else {
                secret.into_bytes()
            }
        }
        None => {
            if let Ok(secret) = rpassword::prompt_password_stderr("Secret: ") {
                if args.base64_secret {
                    base64::decode(secret).unwrap_or_else(|_| {
                        eprintln!("Invalid base64 secret");
                        std::process::exit(-1);
                    })
                } else {
                    secret.into_bytes()
                }
            } else {
                eprintln!("Invalid secret");
                std::process::exit(-2);
            }
        }
    };

    let payload = match args.delimiter {
        Some(delimiter) => args.payload.join(&delimiter),
        None => args.payload.join("\0"),
    };

    let encrypted = crypter::encrypt(&secret, payload.as_bytes()).unwrap_or_else(|| {
        eprintln!("Failed to encrypt");
        std::process::exit(-3);
    });

    if args.raw {
        use std::io::Write;

        let mut stdout = std::io::stdout();
        std::mem::drop(stdout.write_all(&encrypted));
        std::mem::drop(stdout.flush());
    } else {
        print!("{}", base64::encode(encrypted));
    }
}
