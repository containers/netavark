# Contributing to vergen
1. Ensure you have `cargo-clippy` and `rustfmt` installed.  These can be installed via rustup if you don't already have them.
1. Fork the repository
1. Run the following to clone and setup the repository.  There are submodules in the testdata directory used for testing specific git scenarios

    ```
    git clone git@github.com:<your fork>/vergen.git
    cd vergen.git
    git submodule update --init
    ```

1. Install `cargo-all-features`

    ```
    cargo install cargo-all-features
    ```

1. Make your changes
1. Before submitting a PR, make sure you have at least run the following

    ```
    cargo fmt
    cargo clippy --all
    cargo build-all-features
    cargo test-all-features
    ```

1. Push your changes to your fork and submit a PR.
