/*!
 * @brief 원자적으로 통째 교체되는 공유 스냅숏.
 *
 * @details 블록리스트·zone·설정처럼 "읽기가 압도적이고 갱신은 드물게 전면 교체"인 상태의
 *          핫 리로드 경로다.
 */

use std::sync::{Arc, RwLock};

/**
 * @brief 값을 전부 교체할 수 있는 Arc 홀더.
 *
 * @details 이름과 달리 락프리가 아니다. RwLock 기반이며 읽기는 Arc를 복제해
 *          스냅숏을 뜬다. 스냅숏을 뜬 뒤에는 잠금을 놓으므로, 오래 걸리는 질의 처리 중에
 *          갱신이 막히지 않는다. 이미 뜬 스냅숏은 교체 후에도 유효하게 살아 있다.
 * @invariant 모든 잠금 경로가 포이즌을 복구한다. 요청 하나의 패닉으로 이 상태에 영영
 *            접근하지 못하게 되면 서버가 멎는다.
 */
pub struct ArcSwap<T> {
    /** @brief 지금 값. */
    inner: RwLock<Arc<T>>,
}

impl<T> ArcSwap<T> {
    /** @brief 값을 새로 박싱해 홀더를 만든다. */
    pub fn from_pointee(val: T) -> Self {
        Self {
            inner: RwLock::new(Arc::new(val)),
        }
    }

    /** @brief 이미 공유 중인 Arc로 홀더를 만든다. */
    pub fn new(arc: Arc<T>) -> Self {
        Self {
            inner: RwLock::new(arc),
        }
    }

    /**
     * @brief 현재 값의 스냅숏을 뜬다.
     * @note 돌려받은 Arc는 이후 교체와 무관하게 계속 유효하다. 질의 하나가 처리 도중
     *       일관된 상태를 보게 하는 성질이다.
     */
    pub fn load(&self) -> Arc<T> {
        let guard = self
            .inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Arc::clone(&guard)
    }

    /** @brief 값을 전부 교체한다. 이미 뜬 스냅숏은 건드리지 않는다. */
    pub fn store(&self, val: Arc<T>) {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = val;
    }

    /**
     * @brief 현재 값을 읽어 새 값을 만들고 교체한다.
     * @details 쓰기 잠금을 잡은 채 수행하므로 동시 갱신끼리 직렬화된다. load 후 store로
     *          쪼개면 두 갱신이 서로를 덮어쓴다.
     * @warning 클로저 안에서 같은 홀더를 다시 잠그면 교착한다.
     */
    pub fn update(&self, update: impl FnOnce(&T) -> T) {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Arc::new(update(guard.as_ref()));
    }
}

#[cfg(test)]
/** @brief 교체와 동시에 고칠 때의 순서. */
mod tests {
    use super::*;

    #[test]
    /** @brief 넣고 꺼내기. */
    fn load_store() {
        let s = ArcSwap::from_pointee(10u32);
        assert_eq!(*s.load(), 10);
        s.store(Arc::new(20));
        assert_eq!(*s.load(), 20);

        let a = s.load();
        s.store(Arc::new(30));
        assert_eq!(*a, 20);
        assert_eq!(*s.load(), 30);
    }

    #[test]
    /** @brief 동시에 고쳐도 한 번에 하나씩 반영되는지. 안 그러면 한쪽 변경이 사라진다. */
    fn update_serializes_concurrent_writers() {
        let value = Arc::new(ArcSwap::from_pointee(0usize));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let value = value.clone();
            threads.push(std::thread::spawn(move || {
                for _ in 0..1_000 {
                    value.update(|current| current + 1);
                }
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(*value.load(), 8_000);
    }
}
