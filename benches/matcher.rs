use std::{fs, path::PathBuf};

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use time::{macros::datetime, OffsetDateTime};
use veto::{handler, matcher::Matcher, settings};

fn criterion_benchmark(c: &mut Criterion) {
    let matcher = Matcher::with(datetime!(2020-10-04 10:00 UTC));
    let settings = settings::load(Some(PathBuf::from("./benches/matcher.toml"))).unwrap();
    let entry = handler::prepare_rule("web".to_owned(), settings.rules["web"].clone()).unwrap();
    let mut time = OffsetDateTime::UNIX_EPOCH;
    let line = fs::read_to_string("./benches/matcher.txt")
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned();

    let mut g = c.benchmark_group("Matcher");
    g.throughput(Throughput::Elements(1));
    g.bench_function("find", |b| {
        b.iter(|| matcher.find(&entry, &mut time, black_box(&line)))
    });

    g.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
