//! Bounded Core-command acknowledgement dispatch for config activation plans.

use edge_domain::{AppError, CommandAck};
use edge_ports::CoreCommandClient;

use crate::ApplyPlan;

pub(crate) fn send_apply_plan<C>(core: &mut C, plan: &ApplyPlan) -> Result<(), AppError>
where
    C: CoreCommandClient + ?Sized,
{
    for command in plan.commands.iter().cloned() {
        match core.send(command) {
            CommandAck::Accepted => {}
            CommandAck::Rejected(error) => return Err(error),
        }
    }
    Ok(())
}
