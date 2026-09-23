/*!
 * @brief Raft 합의.
 *
 * @details 설정과 상태를 노드 사이에 복제한다. 핵심(raft)은 순수 상태 기계라 입출력을
 *          모르고, transport가 그것을 인증된 네트워크 위에 올린다. 둘을 분리해야
 *          합의 로직을 네트워크 없이 결정적으로 테스트할 수 있다.
 */

/** @brief 합의 알고리즘 본체. */
pub mod raft;
/** @brief 노드 사이를 잇는 인증된 채널. */
pub mod transport;

pub use raft::{Config, LogEntry, Msg, NodeId, Output, RaftNode, Role};
pub use transport::{decode_msg, encode_msg};
