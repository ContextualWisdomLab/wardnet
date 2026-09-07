use wardnet_reputation_core::{
    EvidenceSnapshotV1, REPUTATION_SCHEMA_V1, SourceBatchCompletenessV1,
    SourceGenerationLifecycleCursorV1, SourceGenerationLifecycleErrorV1, SourceReplacementBatchV1,
    SourceSnapshotV1,
};

const NOW: u64 = 1_788_652_800;

fn source_snapshot(source_id: &str, generation: &str, completed_at_unix: u64) -> SourceSnapshotV1 {
    SourceSnapshotV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_owned(),
        source_id: source_id.to_owned(),
        source_generation: generation.to_owned(),
        completed_at_unix,
        valid_until_unix: NOW + 300,
    }
}

fn snapshot(source_id: &str, generation: &str, completed_at_unix: u64) -> EvidenceSnapshotV1 {
    EvidenceSnapshotV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_owned(),
        evidence_generation: "evidence-generation-8".to_owned(),
        source_snapshots: vec![source_snapshot(source_id, generation, completed_at_unix)],
        records: Vec::new(),
    }
}

fn cursor(source_id: &str, generation: &str, ordinal: u64) -> SourceGenerationLifecycleCursorV1 {
    SourceGenerationLifecycleCursorV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_owned(),
        source_id: source_id.to_owned(),
        source_generation: generation.to_owned(),
        source_generation_ordinal: ordinal,
        completed_at_unix: NOW - 30,
    }
}

fn replacement(
    source_id: &str,
    expected_previous_source_generation: Option<&str>,
    generation: &str,
    completed_at_unix: u64,
) -> SourceReplacementBatchV1 {
    SourceReplacementBatchV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_owned(),
        completeness: SourceBatchCompletenessV1::Complete,
        expected_previous_source_generation: expected_previous_source_generation.map(str::to_owned),
        source_snapshot: source_snapshot(source_id, generation, completed_at_unix),
        records: Vec::new(),
    }
}

#[test]
fn source_generation_lifecycle_rejects_aba_replay_after_a_valid_advance() {
    let prior = snapshot("required-source", "generation-8", NOW - 30);
    let retained = cursor("required-source", "generation-8", 8);

    let advanced = prior
        .replace_source_with_lifecycle(
            Some(&retained),
            replacement(
                "required-source",
                Some("generation-8"),
                "generation-9",
                NOW - 20,
            ),
            9,
            "evidence-generation-9",
            NOW,
        )
        .expect("a newer authenticated source generation must advance snapshot and cursor together");

    let replay = replacement(
        "required-source",
        Some("generation-9"),
        "generation-8",
        NOW - 10,
    );
    assert_eq!(
        advanced.evidence_snapshot.replace_source_with_lifecycle(
            Some(&advanced.source_generation_cursor),
            replay,
            8,
            "evidence-generation-10",
            NOW,
        ),
        Err(SourceGenerationLifecycleErrorV1::StaleSourceGenerationOrdinal)
    );
}

#[test]
fn source_generation_lifecycle_rejects_ordinal_token_collision_and_token_rebinding() {
    let retained = cursor("required-source", "generation-8", 8);

    assert_eq!(
        retained.admit(
            &source_snapshot("required-source", "generation-9", NOW - 20),
            8,
            NOW,
        ),
        Err(SourceGenerationLifecycleErrorV1::SourceGenerationOrdinalCollision)
    );
    assert_eq!(
        retained.admit(
            &source_snapshot("required-source", "generation-8", NOW - 20),
            9,
            NOW,
        ),
        Err(SourceGenerationLifecycleErrorV1::ReusedSourceGeneration)
    );
}

#[test]
fn source_generation_lifecycle_rejects_identity_and_completion_substitution() {
    let retained = cursor("required-source", "generation-8", 8);

    assert_eq!(
        retained.admit(
            &source_snapshot("other-source", "generation-9", NOW - 20),
            9,
            NOW,
        ),
        Err(SourceGenerationLifecycleErrorV1::LifecycleIdentityMismatch)
    );
    assert_eq!(
        retained.admit(
            &source_snapshot("required-source", "generation-9", NOW - 31),
            9,
            NOW,
        ),
        Err(SourceGenerationLifecycleErrorV1::SourceCompletionRegression)
    );
}

#[test]
fn replacement_requires_retained_cursor_to_match_the_represented_snapshot() {
    let prior = snapshot("required-source", "generation-8", NOW - 30);
    let wrong_cursor = cursor("required-source", "generation-7", 7);
    let next = replacement(
        "required-source",
        Some("generation-8"),
        "generation-9",
        NOW - 20,
    );

    assert_eq!(
        prior.replace_source_with_lifecycle(
            Some(&wrong_cursor),
            next,
            9,
            "evidence-generation-9",
            NOW,
        ),
        Err(SourceGenerationLifecycleErrorV1::SnapshotCursorMismatch)
    );
}

#[test]
fn source_creation_requires_absent_cursor_and_returns_the_initial_cursor_atomically() {
    let prior = EvidenceSnapshotV1 {
        schema_version: REPUTATION_SCHEMA_V1.to_owned(),
        evidence_generation: "evidence-generation-8".to_owned(),
        source_snapshots: Vec::new(),
        records: Vec::new(),
    };
    let create = replacement("new-source", None, "generation-1", NOW - 20);

    let created = prior
        .replace_source_with_lifecycle(
            None,
            create,
            1,
            "evidence-generation-9",
            NOW,
        )
        .expect("source creation must return snapshot and initial lifecycle cursor together");

    assert_eq!(created.source_generation_cursor.source_id, "new-source");
    assert_eq!(created.source_generation_cursor.source_generation, "generation-1");
    assert_eq!(created.source_generation_cursor.source_generation_ordinal, 1);
    assert_eq!(created.source_generation_cursor.completed_at_unix, NOW - 20);
}
