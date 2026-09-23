/*!
 * @brief 여러 구성 요소가 함께 소유하는 비밀 문자열.
 *
 * @details 복제는 원문 버퍼를 복사하지 않고 참조 수만 늘린다. 마지막 소유자가 사라질
 *          때 버퍼를 지워 설정 재적용과 작업 스레드 생성 과정에 평문 사본이 쌓이지 않는다.
 */

use std::sync::Arc;

use zeroize::Zeroizing;

#[derive(Clone, Default, Eq, PartialEq)]
/** @brief 복제해도 원문 버퍼가 하나뿐인 비밀 문자열. */
pub struct SecretString(Arc<Zeroizing<String>>);

impl SecretString {
    /** @brief 비밀값을 빌린다. */
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(Arc::new(Zeroizing::new(value)))
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        value.to_owned().into()
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl std::ops::Deref for SecretString {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl AsRef<str> for SecretString {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clone_shares_storage_and_debug_redacts() {
        let secret = SecretString::from("top-secret");
        let clone = secret.clone();

        assert_eq!(secret.as_ptr(), clone.as_ptr());
        assert_eq!(format!("{secret:?}"), "<redacted>");
    }
}
