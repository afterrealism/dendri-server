use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dashmap::DashMap;
use std::collections::HashSet;
use std::sync::Arc;

fn bench_dashmap_insert_lookup(c: &mut Criterion) {
    let map: Arc<DashMap<String, String>> = Arc::new(DashMap::new());

    c.bench_function("dashmap insert", |b| {
        let mut i = 0u64;
        b.iter(|| {
            i += 1;
            map.insert(format!("client_{i}"), format!("token_{i}"));
        });
    });

    // Pre-populate
    for i in 0..5000 {
        map.insert(format!("client_{i}"), format!("token_{i}"));
    }

    c.bench_function("dashmap lookup (5000 entries)", |b| {
        let mut i = 0u64;
        b.iter(|| {
            i = (i + 1) % 5000;
            black_box(map.get(&format!("client_{i}")));
        });
    });

    c.bench_function("dashmap iterate (5000 entries)", |b| {
        b.iter(|| {
            let _count: usize = map.iter().count();
        });
    });
}

fn bench_room_fanout(c: &mut Criterion) {
    let rooms: DashMap<String, HashSet<String>> = DashMap::new();
    let mut members = HashSet::new();
    for i in 0..50 {
        members.insert(format!("peer_{i}"));
    }
    rooms.insert("room1".to_string(), members);

    c.bench_function("room fanout (50 members)", |b| {
        b.iter(|| {
            if let Some(members) = rooms.get("room1") {
                let msg = r#"{"type":"DATA","src":"peer_0","payload":{}}"#;
                for member in members.iter() {
                    if member != "peer_0" {
                        black_box(msg);
                    }
                }
            }
        });
    });
}

fn bench_json_serialize(c: &mut Criterion) {
    c.bench_function("manual JSON serialize (relay message)", |b| {
        b.iter(|| {
            let mut out = String::with_capacity(200);
            out.push_str(r#"{"type":"DATA","src":"peer-abc-123","dst":"peer-def-456","payload":{"x":100},"seq":42,"room":"test-room","timestamp":1234567890}"#);
            black_box(out);
        });
    });
}

criterion_group!(
    benches,
    bench_dashmap_insert_lookup,
    bench_room_fanout,
    bench_json_serialize
);
criterion_main!(benches);
