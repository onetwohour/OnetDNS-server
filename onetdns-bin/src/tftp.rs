/*!
 * @brief PXE 부팅용 파일 전송.
 * @note 유닉스에서만 실제 구현이 붙는다. 다른 플랫폼은 아무것도 하지 않는 대체 구현이다.
 */

#[cfg(unix)]
/** @brief 실제 구현. */
mod imp;
#[cfg(unix)]
pub use imp::spawn_tftp;

#[cfg(not(unix))]
/** @brief 대체 구현. */
mod stub;
#[cfg(not(unix))]
pub use stub::spawn_tftp;
