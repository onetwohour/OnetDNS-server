/*!
 * @brief 스레드 로컬 프리리스트를 앞에 둔 전역 할당자.
 *
 * @details 질의 처리는 작고 수명이 짧은 블록을 대량으로 만들었다 버린다. 그 블록을
 *          해제한 스레드가 곧바로 다시 쓰도록 캐시해, 시스템 할당자의 전역 잠금을 피한다.
 *          캐시가 비었거나 만들 수 없으면 언제나 시스템 할당자로 그대로 넘어간다.
 *          이 층은 순수한 최적화이며 없어도 동작이 같아야 한다.
 * @invariant 캐시된 블록은 그 크기 계급의 표준 레이아웃(class_layout)으로 할당·해제된다.
 *            요청 레이아웃과 해제 레이아웃이 어긋나면 미정의 동작이다.
 */

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

/** @brief 계급화가 감당하는 정렬 상한. 넘으면 캐시하지 않는다. */
const MAX_ALIGN: usize = crate::ALLOC_MAX_ALIGN;

/** @brief 크기 계급 목록. */
const CLASSES: [usize; 12] = crate::ALLOC_SIZE_CLASSES;

/**
 * @brief 계급별로 스레드가 잡고 있을 수 있는 블록 수.
 * @details 큰 계급일수록 적게 잡는다. 스레드 하나가 붙들 수 있는 메모리의 상한이
 *          계급 크기 × 이 값의 합이므로, 큰 계급에 같은 수를 주면 스레드마다 수 MiB를 문다.
 */
const SLOT_CAPS: [u8; 12] = [32, 32, 32, 32, 24, 24, 16, 16, 8, 8, 8, 4];

/** @brief 슬롯 배열의 물리적 크기. SLOT_CAPS의 최댓값 이상이어야 한다. */
const MAX_SLOTS: usize = 32;

/** @brief 크기를 담을 수 있는 최소 계급 번호. 0이거나 최대 계급을 넘으면 None. */
fn class_of(size: usize) -> Option<usize> {
    if size == 0 {
        return None;
    }
    CLASSES.iter().position(|&c| size <= c)
}

/**
 * @brief 계급의 표준 레이아웃. 캐시된 블록은 전부 이 레이아웃으로 오간다.
 * @safety CLASSES의 모든 값이 MAX_ALIGN의 배수인 0이 아닌 상수이므로 레이아웃 조건을
 *         항상 만족한다. 테스트 class_boundaries가 이 전제를 고정한다.
 */
fn class_layout(class: usize) -> Layout {
    unsafe { Layout::from_size_align_unchecked(CLASSES[class], MAX_ALIGN) }
}

/** @brief 이 레이아웃을 캐시할 수 있는지와 그 계급. 과한 정렬은 대상에서 뺀다. */
fn cacheable(layout: Layout) -> Option<usize> {
    if layout.align() > MAX_ALIGN {
        return None;
    }
    class_of(layout.size())
}

/**
 * @brief 한 스레드가 잡고 있는 계급별 프리리스트.
 * @invariant counts[c] <= SLOT_CAPS[c] <= MAX_SLOTS. slots[c]의 앞 counts[c]개만 유효하다.
 */
struct ThreadCache {
    /** @brief 등급마다 돌려받아 잡고 있는 블록들. */
    slots: [[*mut u8; MAX_SLOTS]; CLASSES.len()],
    /** @brief 등급마다 잡은 블록 수. */
    counts: [u8; CLASSES.len()],
}

impl ThreadCache {
    /** @brief 빈 캐시. const라 스레드 지역 초기화가 실행 시 비용을 만들지 않는다. */
    const fn new() -> Self {
        Self {
            slots: [[std::ptr::null_mut(); MAX_SLOTS]; CLASSES.len()],
            counts: [0; CLASSES.len()],
        }
    }

    /** @brief 계급에서 블록 하나를 꺼낸다. 비었으면 None. */
    fn pop(&mut self, class: usize) -> Option<*mut u8> {
        let n = self.counts[class];
        if n == 0 {
            return None;
        }
        self.counts[class] = n - 1;
        Some(self.slots[class][usize::from(n) - 1])
    }

    /**
     * @brief 블록을 계급에 되돌린다.
     * @return 슬롯이 없으면 false. 호출자는 그때 시스템 할당자로 진짜 해제해야 한다.
     */
    fn push(&mut self, class: usize, ptr: *mut u8) -> bool {
        let n = self.counts[class];
        if n >= SLOT_CAPS[class] {
            return false;
        }
        self.slots[class][usize::from(n)] = ptr;
        self.counts[class] = n + 1;
        true
    }

    /**
     * @brief 잡고 있던 블록을 전부 시스템에 돌려준다. 스레드 종료 시 불린다.
     * @safety 각 블록은 class_layout(class)로 할당된 것이며 아직 살아 있다. 계급별 개수를
     *         0으로 되돌려 이중 해제를 막는다.
     */
    fn flush(&mut self) {
        for class in 0..CLASSES.len() {
            for i in 0..usize::from(self.counts[class]) {
                unsafe { System.dealloc(self.slots[class][i], class_layout(class)) };
            }
            self.counts[class] = 0;
        }
    }
}

/**
 * @brief pthread 키 초기화 상태.
 * @details 0=미초기화, 1=초기화 중, 2=사용 가능, 3=영구 실패. 3이 있어야 키 생성에 실패한
 *          환경에서 매 할당마다 재시도하지 않는다.
 */
static KEY_STATE: AtomicUsize = AtomicUsize::new(0);

/** @brief 스레드별 캐시를 매다는 pthread 키. KEY_STATE가 2일 때만 유효하다. */
static KEY: AtomicUsize = AtomicUsize::new(0);

/**
 * @brief 스레드 종료 시 캐시를 비우고 해제하는 pthread 소멸자.
 * @safety p는 이 키에 이 서버가 넣은 ThreadCache 포인터이거나 널이다. 다른 값이 들어올
 *         경로가 없으므로 캐스팅이 성립한다.
 */
unsafe extern "C" fn flush_cache(p: *mut libc::c_void) {
    let cache = p.cast::<ThreadCache>();
    if cache.is_null() {
        return;
    }
    unsafe {
        (*cache).flush();
        System.dealloc(cache.cast::<u8>(), Layout::new::<ThreadCache>());
    }
}

/**
 * @brief pthread 키를 한 번만 만들고 그 값을 돌려준다.
 * @details 초기화 중(상태 1)에 들어온 다른 스레드는 None을 받아 그냥 시스템 할당자를
 *          쓴다. 여기서 기다리면 할당 경로에서 잠금 대기가 생긴다.
 * @return 키를 쓸 수 있으면 그 값, 초기화 중이거나 실패했으면 None.
 */
fn cache_key() -> Option<libc::pthread_key_t> {
    match KEY_STATE.load(Ordering::Acquire) {
        2 => Some(KEY.load(Ordering::Relaxed) as libc::pthread_key_t),
        0 => {
            if KEY_STATE
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let mut key: libc::pthread_key_t = 0;
                if unsafe { libc::pthread_key_create(&mut key, Some(flush_cache)) } == 0 {
                    KEY.store(key as usize, Ordering::Relaxed);
                    KEY_STATE.store(2, Ordering::Release);
                    return Some(key);
                }
                KEY_STATE.store(3, Ordering::Release);
            }
            None
        }
        _ => None,
    }
}

/**
 * @brief 이 스레드의 캐시를 얻는다. 없으면 만들어 키에 건다.
 *
 * @details thread_local!을 쓰지 않는 이유는 그 초기화 자체가 할당을 부를 수 있어 전역
 *          할당자 안에서 재귀하기 때문이다. pthread 키는 그 재귀가 없다.
 * @return 캐시 포인터, 또는 키·할당 실패 시 널. 널이면 호출자는 시스템 할당자로 넘어간다.
 * @safety 캐시 블록은 시스템 할당자로 직접 잡고 write로 초기화한다. setspecific이
 *         실패하면 그 자리에서 해제해 누수를 막는다.
 */
fn cache_ptr() -> *mut ThreadCache {
    let Some(key) = cache_key() else {
        return std::ptr::null_mut();
    };
    unsafe {
        let existing = libc::pthread_getspecific(key).cast::<ThreadCache>();
        if !existing.is_null() {
            return existing;
        }
        let block = System
            .alloc(Layout::new::<ThreadCache>())
            .cast::<ThreadCache>();
        if block.is_null() {
            return std::ptr::null_mut();
        }
        block.write(ThreadCache::new());
        if libc::pthread_setspecific(key, block.cast::<libc::c_void>()) != 0 {
            System.dealloc(block.cast::<u8>(), Layout::new::<ThreadCache>());
            return std::ptr::null_mut();
        }
        block
    }
}

/**
 * @brief 이 스레드 캐시에서 블록을 꺼낸다.
 * @safety cache_ptr이 준 포인터는 이 스레드 전용이라 동시 접근이 없다.
 */
fn cache_pop(class: usize) -> Option<*mut u8> {
    let cache = cache_ptr();
    if cache.is_null() {
        return None;
    }
    unsafe { (*cache).pop(class) }
}

/**
 * @brief 블록을 이 스레드 캐시에 넣는다.
 * @note 할당한 스레드가 아니라 해제한 스레드의 캐시로 들어간다. 생산자·소비자 구조에서
 *       블록이 한 방향으로만 흐르면 캐시가 한쪽에 쌓이지만, 상한이 있어 무한정 늘지는 않는다.
 * @safety 위와 같다. 캐시는 스레드 전용이다.
 */
fn cache_push(class: usize, ptr: *mut u8) -> bool {
    let cache = cache_ptr();
    if cache.is_null() {
        return false;
    }
    unsafe { (*cache).push(class, ptr) }
}

/**
 * @brief 스레드 캐시를 앞세운 전역 할당자.
 * @details 캐시가 없거나 대상 크기가 아니면 그대로 시스템 할당자에 위임한다.
 */
pub struct ThreadCachedSystem;

/** @safety 크기와 정렬을 그대로 지켜 시스템 할당기에 넘기거나 같은 등급의 캐시 블록을 준다. */
unsafe impl GlobalAlloc for ThreadCachedSystem {
    /**
     * @brief 캐시에서 먼저 찾고, 없으면 계급 레이아웃으로 새로 잡는다.
     * @safety 캐시된 블록은 같은 계급 레이아웃으로 잡힌 것이라 요청 크기·정렬을 만족한다.
     *         요청보다 큰 블록을 주는 것은 허용된다.
     */
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if let Some(class) = cacheable(layout) {
            if let Some(ptr) = cache_pop(class) {
                return ptr;
            }
            return unsafe { System.alloc(class_layout(class)) };
        }
        unsafe { System.alloc(layout) }
    }

    /**
     * @brief 캐시에 돌려주고, 슬롯이 없으면 시스템에 해제한다.
     * @safety 캐시 대상 블록은 alloc에서 계급 레이아웃으로 잡혔으므로, 해제도 같은
     *         class_layout으로 한다. 호출자가 준 layout을 그대로 쓰면 크기가 어긋난다.
     */
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if let Some(class) = cacheable(layout) {
            if cache_push(class, ptr) {
                return;
            }
            return unsafe { System.dealloc(ptr, class_layout(class)) };
        }
        unsafe { System.dealloc(ptr, layout) }
    }

    /**
     * @brief 크기를 바꾼다. 같은 계급 안이면 아무 일도 하지 않는다.
     *
     * @details 계급이 그대로면 이미 그만큼의 공간이 있으므로 포인터를 그대로 돌려준다.
     *          버퍼를 조금씩 키우는 흔한 패턴에서 복사가 전부 사라진다.
     * @safety 계급이 바뀌는 경우에만 새로 잡아 min(이전 크기, 새 크기)만큼 복사하고 이전 블록을
     *         해제한다. 두 블록은 겹치지 않으므로 copy_nonoverlapping이 성립한다.
     * @return 새 크기의 레이아웃이 유효하지 않으면 널.
     */
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let Ok(new_layout) = Layout::from_size_align(new_size, layout.align()) else {
            return std::ptr::null_mut();
        };
        match (cacheable(layout), cacheable(new_layout)) {
            (Some(old), Some(new)) if old == new => ptr,

            (None, None) => unsafe { System.realloc(ptr, layout, new_size) },

            _ => {
                let new_ptr = unsafe { self.alloc(new_layout) };
                if !new_ptr.is_null() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
                        self.dealloc(ptr, layout);
                    }
                }
                new_ptr
            }
        }
    }
}

#[cfg(test)]
/** @brief 등급 경계, 재사용, 스레드를 넘나드는 반납. */
mod tests {
    use super::*;

    /** @brief 테스트용 할당기. */
    const A: ThreadCachedSystem = ThreadCachedSystem;

    #[test]
    /** @brief 크기가 어느 등급으로 가는지. */
    fn class_boundaries() {
        assert_eq!(class_of(0), None);
        assert_eq!(class_of(1), Some(0));
        assert_eq!(class_of(16), Some(0));
        assert_eq!(class_of(17), Some(1));
        assert_eq!(class_of(2048), Some(CLASSES.len() - 1));
        assert_eq!(class_of(2049), None);
        for (i, &c) in CLASSES.iter().enumerate() {
            assert_eq!(class_of(c), Some(i), "정확히 클래스 크기");
            assert_eq!(c % MAX_ALIGN, 0, "클래스는 16의 배수");
        }
    }

    #[test]
    /** @brief 돌려준 블록을 다시 쓰면서 내용이 어긋나지 않는지. */
    fn roundtrip_reuses_cached_block_and_preserves_writes() {
        let layout = Layout::from_size_align(100, 8).unwrap();
        unsafe {
            let p1 = A.alloc(layout);
            assert!(!p1.is_null());
            std::ptr::write_bytes(p1, 0xA5, 100);
            A.dealloc(p1, layout);

            let p2 = A.alloc(Layout::from_size_align(128, 8).unwrap());
            assert_eq!(p1, p2, "클래스(128) 캐시 재사용");
            std::ptr::write_bytes(p2, 0x5A, 128);
            assert_eq!(*p2.add(127), 0x5A);
            A.dealloc(p2, Layout::from_size_align(128, 8).unwrap());
        }
    }

    #[test]
    /** @brief 등급에 맞지 않는 요청은 시스템 할당기로 그냥 넘기는지. */
    fn oversized_and_overaligned_pass_through() {
        unsafe {
            let big = Layout::from_size_align(4096, 8).unwrap();
            let p = A.alloc(big);
            assert!(!p.is_null());
            std::ptr::write_bytes(p, 1, 4096);
            A.dealloc(p, big);

            let aligned = Layout::from_size_align(64, 64).unwrap();
            let p = A.alloc(aligned);
            assert!(!p.is_null());
            assert_eq!(p as usize % 64, 0);
            A.dealloc(p, aligned);
        }
    }

    #[test]
    /** @brief 비워 달라고 하면 앞 내용이 남지 않는지. 남으면 남의 자료가 새 나간다. */
    fn alloc_zeroed_after_dirty_reuse_is_zero() {
        let layout = Layout::from_size_align(64, 8).unwrap();
        unsafe {
            let p = A.alloc(layout);
            std::ptr::write_bytes(p, 0xFF, 64);
            A.dealloc(p, layout);
            let z = A.alloc_zeroed(layout);
            for i in 0..64 {
                assert_eq!(*z.add(i), 0, "재사용 블록도 0으로 초기화");
            }
            A.dealloc(z, layout);
        }
    }

    #[test]
    /** @brief 같은 등급 안에서는 곳을 옮기지 않는지. */
    fn realloc_within_class_is_in_place_and_across_class_copies() {
        let layout = Layout::from_size_align(70, 8).unwrap();
        unsafe {
            let p = A.alloc(layout);
            for i in 0..70u8 {
                *p.add(usize::from(i)) = i;
            }

            let q = A.realloc(p, layout, 90);
            assert_eq!(p, q);

            let r = A.realloc(q, Layout::from_size_align(90, 8).unwrap(), 300);
            assert!(!r.is_null());
            for i in 0..70u8 {
                assert_eq!(*r.add(usize::from(i)), i);
            }
            A.dealloc(r, Layout::from_size_align(300, 8).unwrap());
        }
    }

    #[test]
    /** @brief 다른 스레드에서 돌려준 블록이 그 스레드 캐시로 가는지. 원래 스레드로 보내면 그것이 경합이다. */
    fn cross_thread_free_lands_in_freeing_threads_cache() {
        let layout = Layout::from_size_align(256, 8).unwrap();
        let ptr = unsafe { A.alloc(layout) } as usize;
        let handle = std::thread::spawn(move || {
            unsafe { A.dealloc(ptr as *mut u8, layout) };

            let again = unsafe { A.alloc(layout) } as usize;
            assert_eq!(again, ptr);
            unsafe { A.dealloc(again as *mut u8, layout) };
        });
        handle.join().unwrap();
    }

    #[test]
    /** @brief 여러 스레드가 두드려도 내용이 섞이지 않는지. */
    fn multithread_stress_with_pattern_integrity() {
        let mut handles = Vec::new();
        for t in 0..8u8 {
            handles.push(std::thread::spawn(move || {
                let mut state = u64::from(t) * 2654435761 + 1;
                let mut lcg = move || {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    state
                };
                let mut live: Vec<(usize, Layout, u8)> = Vec::new();
                for _ in 0..20_000 {
                    if live.len() < 32 && lcg() % 3 != 0 {
                        let size = (lcg() % 3000 + 1) as usize;
                        let layout = Layout::from_size_align(size, 8).unwrap();
                        let p = unsafe { A.alloc(layout) };
                        assert!(!p.is_null());
                        let tag = (lcg() & 0xFF) as u8;
                        unsafe { std::ptr::write_bytes(p, tag, size) };
                        live.push((p as usize, layout, tag));
                    } else if let Some((p, layout, tag)) = live.pop() {
                        unsafe {
                            for i in [0, layout.size() / 2, layout.size() - 1] {
                                assert_eq!(*(p as *mut u8).add(i), tag, "블록 내용 무결성");
                            }
                            A.dealloc(p as *mut u8, layout);
                        }
                    }
                }
                for (p, layout, tag) in live {
                    unsafe {
                        assert_eq!(*(p as *mut u8), tag);
                        A.dealloc(p as *mut u8, layout);
                    }
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }
}
