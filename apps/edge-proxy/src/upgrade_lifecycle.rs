//! Offline upgrade and recovery CLI orchestration.
//!
//! This bootstrap adapter selects the explicitly requested deployment helper and
//! renders the stable, secret-free maintenance result. It does not parse process
//! arguments, read environment variables, or start the proxy runtime.

use crate::{app_error_to_io, process_mode};
use edge_adapters::{
    CommandOfflineUpgradeDeployment, ComposeUpgradeHelperRunner, FileOfflineUpgradeJournalStore,
    SystemUpgradeHelperProcessExecutor, SystemdUpgradeHelperRunner, UpgradeHelperProcessExecutor,
};
use edge_application::{execute_journaled_offline_upgrade_with_receipt, recover_offline_upgrade};
use edge_domain::{AppError, OfflineUpgradeState};

pub(crate) fn run_upgrade(options: process_mode::UpgradeOptions) -> std::io::Result<()> {
    let receipt = run_upgrade_with_executor(options, SystemUpgradeHelperProcessExecutor)
        .map_err(app_error_to_io)?;
    println!(
        "{}",
        render_upgrade_result(&receipt.operation_id, receipt.state)
    );
    Ok(())
}

pub(crate) fn run_upgrade_with_executor<E: UpgradeHelperProcessExecutor>(
    options: process_mode::UpgradeOptions,
    executor: E,
) -> Result<edge_application::OfflineUpgradeExecutionReceipt, AppError> {
    let mut journals = FileOfflineUpgradeJournalStore::new(&options.data_dir)?;
    match options.deployment {
        process_mode::UpgradeDeployment::Systemd => {
            let mut deployment =
                CommandOfflineUpgradeDeployment::new(SystemdUpgradeHelperRunner::new(executor));
            execute_journaled_offline_upgrade_with_receipt(
                &mut deployment,
                &mut journals,
                options.request,
            )
        }
        process_mode::UpgradeDeployment::Compose => {
            let mut deployment =
                CommandOfflineUpgradeDeployment::new(ComposeUpgradeHelperRunner::new(executor));
            execute_journaled_offline_upgrade_with_receipt(
                &mut deployment,
                &mut journals,
                options.request,
            )
        }
    }
}

pub(crate) fn run_upgrade_recover(
    options: process_mode::UpgradeRecoverOptions,
) -> std::io::Result<()> {
    let state =
        run_upgrade_recover_with_executor(options.clone(), SystemUpgradeHelperProcessExecutor)
            .map_err(app_error_to_io)?;
    println!("{}", render_upgrade_result(&options.operation_id, state));
    Ok(())
}

pub(crate) fn run_upgrade_recover_with_executor<E: UpgradeHelperProcessExecutor>(
    options: process_mode::UpgradeRecoverOptions,
    executor: E,
) -> Result<OfflineUpgradeState, AppError> {
    let mut journals = FileOfflineUpgradeJournalStore::new(&options.data_dir)?;
    match options.deployment {
        process_mode::UpgradeDeployment::Systemd => {
            let mut deployment =
                CommandOfflineUpgradeDeployment::new(SystemdUpgradeHelperRunner::new(executor));
            recover_offline_upgrade(&mut deployment, &mut journals, &options.operation_id)
        }
        process_mode::UpgradeDeployment::Compose => {
            let mut deployment =
                CommandOfflineUpgradeDeployment::new(ComposeUpgradeHelperRunner::new(executor));
            recover_offline_upgrade(&mut deployment, &mut journals, &options.operation_id)
        }
    }
}

pub(crate) fn render_upgrade_result(operation_id: &str, state: OfflineUpgradeState) -> String {
    let state = match state {
        OfflineUpgradeState::Committed => "committed",
        OfflineUpgradeState::RolledBack => "rolled_back",
        _ => "incomplete",
    };
    serde_json::json!({ "result_schema_version": 1, "operation_id": operation_id, "state": state })
        .to_string()
}
