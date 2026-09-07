use wardnet_reputation_core::model::EvidenceRecordV1;

#[test]
fn existing_model_namespace_remains_public_for_unaffected_contract_types() {
    let _ = std::any::TypeId::of::<EvidenceRecordV1>();
}
