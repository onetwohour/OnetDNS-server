/*!
 * @brief 오류에 문맥을 붙이는 도구.
 *
 * @details 어느 파일을 열다 실패했는지 같은 정보가 없으면 오류 메시지만으로 원인을
 *          찾을 수 없다.
 */

/** @brief 시작 경로에서 쓰는 결과 형. 오류 종류를 세세히 나누지 않는다. */
pub type BoxResult<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/** @brief 오류에 설명을 덧붙이는 확장. */
pub trait Context<T> {
    /** @brief 실패했을 때만 설명을 만들어 붙인다. 성공 경로에는 비용이 없다. */
    fn with_context<C: std::fmt::Display, F: FnOnce() -> C>(self, f: F) -> BoxResult<T>;
}

impl<T, E: std::error::Error + Send + Sync + 'static> Context<T> for std::result::Result<T, E> {
    /** @brief 실패에 맥락을 덧붙인다. 어디서 났는지 알 수 없으면 고칠 수 없다. */
    fn with_context<C: std::fmt::Display, F: FnOnce() -> C>(self, f: F) -> BoxResult<T> {
        self.map_err(|e| format!("{}: {e}", f()).into())
    }
}

#[macro_export]
macro_rules! anyhow {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {
        ::std::boxed::Box::<dyn ::std::error::Error + Send + Sync>::from(format!($fmt $(, $arg)*))
    };
    ($e:expr) => {
        ::std::boxed::Box::<dyn ::std::error::Error + Send + Sync>::from(format!("{}", $e))
    };
}

#[macro_export]
macro_rules! bail {
    ($($t:tt)*) => {
        return ::std::result::Result::Err($crate::anyhow!($($t)*))
    };
}
