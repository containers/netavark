use std::sync::Mutex;

use easy_parallel::Parallel;

#[test]
fn smoke() {
    let m = Mutex::new(0);
    let v = vec![2, 3, 5, 7, 11];

    Parallel::new()
        .add(|| *m.lock().unwrap() += 10)
        .add(|| *m.lock().unwrap() += 20)
        .each(v.iter(), |n| *m.lock().unwrap() += *n)
        .run();

    assert_eq!(m.into_inner().unwrap(), 10 + 20 + v.iter().sum::<i32>());
}

#[test]
fn squares() {
    let v = vec![10, 20, 30];

    let squares = Parallel::new()
        .each(0..v.len(), |i| v[i] * v[i])
        .run();

    assert_eq!(squares, [100, 400, 900]);
}

#[test]
fn finish() {
    let v = vec![10, 20, 30];

    let (squares, len) = Parallel::new()
        .each(0..v.len(), |i| v[i] * v[i])
        .finish(|| v.len());

    assert_eq!(squares, [100, 400, 900]);
    assert_eq!(len, 3);
}
