use easy_parallel::Parallel;

fn par_sum(v: &[i32]) -> i32 {
    const THRESHOLD: usize = 100;

    if v.len() <= THRESHOLD {
        v.iter().copied().sum()
    } else {
        let half = (v.len() + 1) / 2;
        let sums = Parallel::new().each(v.chunks(half), par_sum).run();
        sums.into_iter().sum()
    }
}

fn main() {
    let mut v = Vec::new();
    for i in 0..10_000 {
        v.push(i);
    }

    let sum = dbg!(par_sum(&v));
    assert_eq!(sum, v.into_iter().sum());
}
