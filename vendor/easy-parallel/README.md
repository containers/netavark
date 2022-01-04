# easy-parallel

[![Build](https://github.com/smol-rs/easy-parallel/workflows/Build%20and%20test/badge.svg)](
https://github.com/smol-rs/easy-parallel/actions)
[![License](https://img.shields.io/badge/license-Apache--2.0_OR_MIT-blue.svg)](
https://github.com/smol-rs/easy-parallel)
[![Cargo](https://img.shields.io/crates/v/easy-parallel.svg)](
https://crates.io/crates/easy-parallel)
[![Documentation](https://docs.rs/easy-parallel/badge.svg)](
https://docs.rs/easy-parallel)

Run closures in parallel.

This is a simple primitive for spawning threads in bulk and waiting for them to complete.
Threads are allowed to borrow local variables from the main thread.

# Examples

Run two threads that increment a number:

```rust
use easy_parallel::Parallel;
use std::sync::Mutex;

let mut m = Mutex::new(0);

Parallel::new()
    .add(|| *m.lock().unwrap() += 1)
    .add(|| *m.lock().unwrap() += 1)
    .run();

assert_eq!(*m.get_mut().unwrap(), 2);
```

Square each number of a vector on a different thread:

```rust
use easy_parallel::Parallel;

let v = vec![10, 20, 30];

let squares = Parallel::new()
    .each(0..v.len(), |i| v[i] * v[i])
    .run();

assert_eq!(squares, [100, 400, 900]);
```

Compute the sum of numbers in an array:

```rust
use easy_parallel::Parallel;

fn par_sum(v: &[i32]) -> i32 {
    const THRESHOLD: usize = 2;

    if v.len() <= THRESHOLD {
        v.iter().copied().sum()
    } else {
        let half = (v.len() + 1) / 2;
        let sums = Parallel::new().each(v.chunks(half), par_sum).run();
        sums.into_iter().sum()
    }
}

let v = [1, 25, -4, 10, 8];
assert_eq!(par_sum(&v), 40);
```

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

#### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
