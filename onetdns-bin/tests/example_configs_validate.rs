/*!
 * @brief 저장소에 든 예제 설정이 실제로 읽히고 통과하는지.
 *
 * @details 문서에 적힌 설정이 지금 코드에서 안 되면 그대로 따라 한 운영자가 시작에
 *          실패한다. 설정 항목을 바꿀 때 예제도 함께 고치게 하려는 것이다.
 */

use std::path::{Path, PathBuf};

use onetdns_config::Config;

/** @brief 예제 설정을 찾을 디렉터리들. */
const EXAMPLE_DIRS: &[&str] = &["benchmarks", "examples", "docs"];
/**
 * @brief 서버 설정이 아닌 TOML 파일들.
 *
 * @details 이 검사는 디렉터리를 훑어 TOML 을 전부 서버 설정으로 읽는다. 같은 위치에 다른
 *          용도의 TOML 을 두면 여기에 적어야 한다. architecture.toml 은 문서 소유 범위를
 *          적어 둔 명세이고 docs_drift 가 읽는다.
 */
const SKIP_FILE_NAMES: &[&str] = &["Cargo.toml", "deny.toml", "architecture.toml"];

/** @brief 디렉터리에서 설정 파일들을 모은다. */
fn collect_tomls(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_tomls(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "toml")
            && path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| !SKIP_FILE_NAMES.contains(&name))
        {
            out.push(path);
        }
    }
}

#[test]
/** @brief 예제 설정이 모두 읽히고 검사를 통과하는지. */
fn repo_example_configs_parse_and_validate() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("작업공간의 최상위 디렉터리가 있어야 합니다")
        .to_path_buf();
    let mut files = Vec::new();
    for dir in EXAMPLE_DIRS {
        collect_tomls(&root.join(dir), &mut files);
    }
    assert!(
        !files.is_empty(),
        "예제 설정을 찾지 못했습니다. 예제 디렉터리를 옮겼다면 EXAMPLE_DIRS 목록을 갱신해야 합니다"
    );
    for path in files {
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("{} 읽지 못했습니다: {error}", path.display()));
        let config = Config::from_toml_str(&text)
            .unwrap_or_else(|error| panic!("{} 해석하지 못했습니다: {error:?}", path.display()));
        config
            .validate()
            .unwrap_or_else(|error| panic!("{} 검증에 실패했습니다: {error:?}", path.display()));
    }
}
