use async_broadcast::broadcast;
use criterion::{criterion_group, criterion_main, Criterion};
use futures_lite::future::block_on;
pub fn broadcast_and_recv(c: &mut Criterion) {
    let (s, mut r1) = broadcast(1);

    let mut n = 0;
    c.bench_function("1 -> 1", |b| {
        b.iter(|| {
            block_on(async {
                s.broadcast(n).await.unwrap();
                assert_eq!(r1.recv().await.unwrap(), n);
                n += 1;
            })
        })
    });

    let mut r2 = r1.clone();

    c.bench_function("1 -> 2", |b| {
        b.iter(|| {
            block_on(async {
                s.broadcast(n).await.unwrap();
                assert_eq!(r1.recv().await.unwrap(), n);
                assert_eq!(r2.recv().await.unwrap(), n);
                n += 1;
            })
        })
    });
}

criterion_group!(benches, broadcast_and_recv);
criterion_main!(benches);
