
![Image](Sprite-0001.png)

# Overview

[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE.txt)
[![GitHub release](https://img.shields.io/github/release/fresh-milkshake/zip-cracker.svg)](https://github.com/fresh-milkshake/zip-cracker/releases)
[![Rust](https://img.shields.io/badge/rust-1.86.0-dd3516.svg)](https://www.rust-lang.org/)
[![Downloads](https://img.shields.io/github/downloads/fresh-milkshake/zip-cracker/total.svg)](https://github.com/fresh-milkshake/zip-cracker/releases)

Zip Cracker is a ~~powerful~~, modern, and ~~efficient~~ tool for cracking password-protected ZIP files. Utilizing Rust's performance capabilities and parallel computing, this tool provides a fast and convenient solution for recovering lost or forgotten passwords for encrypted ZIP files. The program supports both dictionary-based and brute-force attacks.

## Features

- Multithreaded password cracking for maximum performance
- Dictionary-based attack using custom wordlists
- Brute-force attack with adjustable character sets and lengths
- Progress bar for real-time updates on cracking progress

## Installation

### Manual Installation (Recommended)

You can download the precompiled binaries from the [Releases](https://github.com/fresh-milkshake/zip-cracker/releases) page.

### Quick Install

#### Linux/macOS

```bash
curl -sSL https://raw.githubusercontent.com/fresh-milkshake/zip-cracker/master/scripts/install.sh | bash
```

#### Windows (PowerShell)

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fresh-milkshake/zip-cracker/master/scripts/install.ps1" -UseBasicParsing | Invoke-Expression
```

## Usage

Zip Cracker provides an easy-to-use command-line interface for cracking password-protected ZIP files. Here's a quick overview of how to use the tool:

1. Dictionary-based attack:

    ```bash
    zip-cracker /path/to/encrypted.zip -d /path/to/dictionary.txt
    ```

2. Brute-force attack:

    ```bash
    zip-cracker /path/to/encrypted.zip -g
    ```

3. Display help:

    ```bash
    $ zip-cracker --help
    
    Zip Bruteforce
    
    USAGE:
        main.exe [OPTIONS] <FILE>
    
    ARGS:
        <FILE>    The zip file to bruteforce
    
    OPTIONS:
        -d, --dict <FILE>    Path to the dictionary to use for bruteforce
        -g, --generate       Use brute-force generation
        -h, --help           Print help information
        -v, --verbose        Prints more information
    ```

## Building from Source

To build Zip Cracker from source, follow these steps:

1. Install Rust using [rustup](https://rustup.rs/):

    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```

2. Clone the repository:

    ```bash
    git clone https://github.com/fresh-milkshake/zip-cracker
    ```

3. Change to the project directory:

    ```bash
    cd zip-cracker
    ```

4. Build the project:

    ```bash
    cargo build --release
    ```

5. The compiled binary can be found in `target/release/zip-cracker`.

## License

This project is licensed under the [MIT License](LICENSE.txt). Please see the [LICENSE](LICENSE.txt) file for more information.

---

<p align="center">
    <strong>If you like this project, please consider giving it a ⭐️ on GitHub!</strong>
</p>
