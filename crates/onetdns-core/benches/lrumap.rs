use std::alloc::{alloc_zeroed, dealloc, handle_alloc_error, GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::ptr::NonNull;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{fence, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use onetdns_core::{alloc_class_size, LruMap};

/** @brief 측정할 때 쓰는 용량. */
const CAPACITY: usize = 20_000;
/** @brief 미리 채워 둘 개수. */
const FILL: usize = 10_000;
/** @brief 키 길이. */
const KEY_LEN: usize = 30;
/** @brief 값 길이. */
const STORAGE_LEN: usize = 62;
/** @brief 조회 반복 횟수. */
const GET_ITERATIONS: usize = 10_000_000;
/** @brief 넣기 반복 횟수. */
const PUT_ITERATIONS: usize = 1_000_000;

/** @brief 실제로 잡힌 메모리를 세는 할당기. */
struct CountingAllocator;

/** @brief 지금 잡혀 있는 바이트. */
static LIVE_BYTES: AtomicUsize = AtomicUsize::new(0);

/** @brief 측정하는 대상이 잡은 바이트. */
static LIVE_CLASS_BYTES: AtomicUsize = AtomicUsize::new(0);

/** @brief 잡은 만큼 센다. */
fn track_alloc(layout: Layout) {
    LIVE_BYTES.fetch_add(layout.size(), Ordering::Relaxed);
    LIVE_CLASS_BYTES.fetch_add(
        alloc_class_size(layout.size(), layout.align()),
        Ordering::Relaxed,
    );
}

/** @brief 돌려준 만큼 뺀다. */
fn track_dealloc(layout: Layout) {
    LIVE_BYTES.fetch_sub(layout.size(), Ordering::Relaxed);
    LIVE_CLASS_BYTES.fetch_sub(
        alloc_class_size(layout.size(), layout.align()),
        Ordering::Relaxed,
    );
}

/** @safety 세기만 하고 실제 할당은 시스템 할당기에 그대로 넘긴다. */
unsafe impl GlobalAlloc for CountingAllocator {
    /** @brief 잡고 센다. */
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            track_alloc(layout);
        }
        pointer
    }

    /** @brief 돌려주고 뺀다. */
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        track_dealloc(layout);
        unsafe { System.dealloc(pointer, layout) };
    }

    /** @brief 비워서 잡고 센다. */
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            track_alloc(layout);
        }
        pointer
    }

    /** @brief 크기를 바꾸고 셈을 맞춘다. */
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_pointer = unsafe { System.realloc(pointer, layout, new_size) };
        if !new_pointer.is_null() {
            track_dealloc(layout);
            let grown = Layout::from_size_align(new_size, layout.align())
                .expect("realloc 레이아웃은 원래 정렬로 유효해야 한다");
            track_alloc(grown);
        }
        new_pointer
    }
}

#[global_allocator]
/** @brief 이 벤치가 쓰는 할당기. */
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[allow(dead_code)]
/** @brief 실제 캐시 항목과 크기를 맞춘 테스트용 값. */
enum ProbeEntry {
    /** @brief 레코드로 담은 항목과 크기를 맞춘 것. */
    Structured(Arc<()>),
    /** @brief 바이트로 담은 항목과 크기를 맞춘 것. */
    Wire(ProbeWireRef),
}

#[repr(C)]
#[allow(dead_code)]
/** @brief 실제 저장 형태와 크기를 맞춘 헤더. */
struct ProbeWireAllocation {
    /** @brief 담은 시각. */
    inserted_nanos: i64,
    /** @brief 담을 때의 세대. */
    filter_tag: usize,
    /** @brief 소유자 수. */
    refs: AtomicU32,
    /** @brief 이어진 내용의 길이. */
    storage_len: u32,
    /** @brief 이 항목의 수명. */
    lifetime_secs: u32,
    /** @brief 응답 바이트의 길이. */
    wire_len: u16,
    /** @brief TTL 테이블의 항목 수. */
    ttl_count: u16,
}

/** @brief 위 헤더를 가리키는 소유자. */
struct ProbeWireRef(NonNull<ProbeWireAllocation>);

impl ProbeWireRef {
    /** @brief 하나 잡는다. */
    fn new(_inserted: Instant) -> Self {
        let layout = probe_wire_layout();
        let raw = unsafe { alloc_zeroed(layout) };
        let Some(pointer) = NonNull::new(raw.cast::<ProbeWireAllocation>()) else {
            handle_alloc_error(layout);
        };
        unsafe {
            pointer.as_ptr().write(ProbeWireAllocation {
                inserted_nanos: 0,
                filter_tag: 1,
                refs: AtomicU32::new(1),
                storage_len: STORAGE_LEN as u32,
                lifetime_secs: 300,
                wire_len: 54,
                ttl_count: 1,
            });
        }
        Self(pointer)
    }
}

impl Drop for ProbeWireRef {
    /** @brief 돌려준다. */
    fn drop(&mut self) {
        let allocation = unsafe { self.0.as_ref() };
        assert_eq!(allocation.refs.fetch_sub(1, Ordering::Release), 1);
        fence(Ordering::Acquire);
        unsafe { dealloc(self.0.as_ptr().cast(), probe_wire_layout()) };
    }
}

/** @brief 테스트용 값의 배치. */
fn probe_wire_layout() -> Layout {
    Layout::from_size_align(
        std::mem::size_of::<ProbeWireAllocation>() + STORAGE_LEN,
        std::mem::align_of::<ProbeWireAllocation>(),
    )
    .unwrap()
}

/** @brief 이 번호의 키. */
fn key(index: usize) -> Vec<u8> {
    let mut key = vec![0u8; KEY_LEN];
    key[..8].copy_from_slice(&(index as u64).to_le_bytes());
    key
}

/** @brief 테스트용 값 하나. */
fn entry(inserted: Instant) -> ProbeEntry {
    ProbeEntry::Wire(ProbeWireRef::new(inserted))
}

/** @brief 조회·넣기 비용과 항목당 메모리를 측정한다. */
fn main() {
    assert_eq!(std::mem::size_of::<ProbeEntry>(), 16);
    assert_eq!(std::mem::size_of::<ProbeWireRef>(), 8);
    assert_eq!(std::mem::size_of::<ProbeWireAllocation>(), 32);
    assert_eq!(probe_wire_layout().size(), 94);

    let keys: Vec<Vec<u8>> = (0..FILL).map(key).collect();
    let before_map = LIVE_BYTES.load(Ordering::Relaxed);
    let before_class = LIVE_CLASS_BYTES.load(Ordering::Relaxed);
    let mut map = LruMap::new(CAPACITY);
    let empty_map_bytes = LIVE_BYTES.load(Ordering::Relaxed) - before_map;
    let empty_map_class_bytes = LIVE_CLASS_BYTES.load(Ordering::Relaxed) - before_class;
    let inserted = Instant::now();
    for key in &keys {
        map.put(key.clone().into_boxed_slice(), entry(inserted));
    }
    let retained_bytes = LIVE_BYTES.load(Ordering::Relaxed) - before_map;
    let retained_class_bytes = LIVE_CLASS_BYTES.load(Ordering::Relaxed) - before_class;
    let filled_bytes = retained_bytes - empty_map_bytes;

    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let started = Instant::now();
    for _ in 0..GET_ITERATIONS {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let index = state as usize % FILL;
        black_box(map.get(keys[index].as_slice()));
    }
    let get_elapsed = started.elapsed();

    let started = Instant::now();
    for index in FILL..FILL + PUT_ITERATIONS {
        map.put(key(index).into_boxed_slice(), entry(inserted));
    }
    let put_elapsed = started.elapsed();

    println!(
        "cache-model(capacity={CAPACITY} fill={FILL} key={KEY_LEN}B storage={STORAGE_LEN}B): preallocated={}B filled={}B ({:.1}B/filled-entry requested, {:.1}B/filled-entry musl-class) retained={}B (class {}B) get-hit={:.2} ns/op put-evict={:.2} ns/op",
        empty_map_bytes,
        filled_bytes,
        filled_bytes as f64 / FILL as f64,
        (retained_class_bytes - empty_map_class_bytes) as f64 / FILL as f64,
        retained_bytes,
        retained_class_bytes,
        get_elapsed.as_nanos() as f64 / GET_ITERATIONS as f64,
        put_elapsed.as_nanos() as f64 / PUT_ITERATIONS as f64,
    );
}
