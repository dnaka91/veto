use std::fs;
use std::path::PathBuf;

use chrono::prelude::*;
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use veto::handler;
use veto::matcher::Matcher;
use veto::settings;

fn criterion_benchmark(c: &mut Criterion) {
    let matcher = Matcher::with(Utc.ymd(2020, 10, 4).and_hms(10, 0, 0));
    let settings = settings::load(Some(PathBuf::from("./benches/matcher.toml"))).unwrap();
    let entry = handler::prepare_rule("web".to_owned(), settings.rules["web"].clone()).unwrap();
    let mut time = Utc.timestamp(0, 0);
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
