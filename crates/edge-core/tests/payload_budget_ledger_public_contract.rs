use edge_core::{PayloadBudgetLedger, PayloadClass, ResourcePressureState};
use edge_domain::RuntimeResourcePolicy;

#[test]
fn payload_budget_ledger_contract_remains_available_from_the_crate_root() {
    let policy = RuntimeResourcePolicy::default();
    let mut ledger = PayloadBudgetLedger::new(policy, 9);
    let charge = ledger.reserve(1, PayloadClass::Request, 4, 9).unwrap();

    assert_eq!(ledger.used_bytes(), 4);
    assert_eq!(ledger.pressure_state(), ResourcePressureState::Normal);
    ledger.release(charge, 9).unwrap();
    assert_eq!(ledger.used_bytes(), 0);
}
