# Zip Cracker

Zip Cracker is a ~~powerful~~, modern, and ~~efficient~~ tool for cracking password-protected ZIP files. Utilizing Rust's performance capabilities and parallel computing, this tool provides a fast and convenient solution for recovering lost or forgotten passwords for encrypted ZIP files. The program supports both dictionary-based and brute-force attacks.

## Features

- Multithreaded password cracking for maximum performance
- Dictionary-based attack using custom wordlists
- Brute-force attack with adjustable character sets and lengths
- Progress bar for real-time updates on cracking progress

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Building from Source](#building-from-source)
- [Contributing](#contributing)
- [License](#license)

## Installation

You can download the precompiled binaries for Windows from the [Releases](https://github.com/fresh-milkshake/zip-cracker/releases) page. Extract the archive and place the binary in a directory listed in your system's `PATH` environment variable for easy access.

## Usage

Zip Cracker provides an easy-to-use command-line interface for cracking password-protected ZIP files. Here's a quick overview of how to use the tool:

1. Dictionary-based attack:
    
    ```bash
    $ zip-cracker /path/to/encrypted.zip -d /path/to/dictionary.txt
    ```

2. Brute-force attack:

    ```bash
    $ zip-cracker /path/to/encrypted.zip -g
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
    $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```

2. Clone the repository:

    ```bash
    $ git clone https://github.com/yourusername/zip-cracker.git
    ```

3. Change to the project directory:

    ```bash
    $ cd zip-cracker
    ```

4. Build the project:

    ```bash
    $ cargo build --release
    ```

5. The compiled binary can be found in `target/release/zip-cracker`.

## Contributing

We welcome contributions to the Zip Cracker project! If you're interested in contributing, please follow these steps:

1. Fork the repository.
2. Create a new branch with a descriptive name.
3. Commit your changes to the new branch.
4. Create a pull request describing the changes you've made.
5. We'll review your pull request and provide feedback or merge it if everything looks good.

## License

This project is licensed under the [MIT License](LICENSE.txt). Please see the [LICENSE](LICENSE.txt) file for more information.
