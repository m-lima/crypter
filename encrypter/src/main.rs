#![deny(warnings, clippy::pedantic, clippy::all, rust_2018_idioms)]

use std::io::Write;

#[derive(clap::Parser, Debug)]
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

fn main() -> std::process::ExitCode {
    if let Err(err) = fallible_main() {
        eprintln!("{err}");
        std::process::ExitCode::FAILURE
    } else {
        std::process::ExitCode::SUCCESS
    }
}

fn fallible_main() -> Result<(), &'static str> {
    let args = <Args as clap::Parser>::parse();

    if args.payload.is_empty() {
        return Err("Nothing to encrypt");
    }

    let secret = args
        .secret
        .or_else(|| rpassword::prompt_password_stderr("Secret: ").ok())
        .ok_or("Missing secret")?;

    let secret = if args.base64_secret {
        base64::decode(secret).map_err(|_| "Invalid base64 secret")?
    } else {
        secret.into_bytes()
    };

    let payload = match args.delimiter {
        Some(delimiter) => args.payload.join(&delimiter),
        None => args.payload.join("\0"),
    };

    let encrypted = crypter::encrypt(secret, payload.as_bytes()).ok_or("Failed to encrypt")?;

    let mut stdout = std::io::stdout().lock();
    if args.raw {
        stdout.write_all(&encrypted)
    } else {
        write!(stdout, "{}", base64::encode(encrypted))
    }
    .map_err(|_| "Failed to write to stdout")
}
