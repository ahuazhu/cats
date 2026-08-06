use std::{fs, path::Path};

#[test]
fn ordinary_ci_covers_exact_rc_push_without_privileged_permissions() {
    let workflow = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.github/workflows/ci.yml"),
    )
    .expect("read CI workflow");

    assert!(workflow.contains("      - rc/architecture-v2\n"));
    assert!(workflow.contains("permissions:\n  contents: read\n"));
    assert_eq!(
        workflow
            .matches("          ref: ${{ github.sha }}\n")
            .count(),
        2
    );
    assert!(!workflow.contains("id-token: write"));
    assert!(!workflow.contains("configure-aws-credentials"));
    assert!(!workflow.contains("environment: production"));
}
