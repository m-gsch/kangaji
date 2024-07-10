use libafl::{inputs::UsesInput, observers::Observer};
use libafl_bolts:: Named;
use serde::{Deserialize, Serialize};

#[derive(Default,Deserialize,Serialize)]
pub struct CoverageBreakpointObserver {
    pub hit: bool,
}

impl<S> Observer<S> for CoverageBreakpointObserver
where
    S: UsesInput,
{
    fn pre_exec(
        &mut self,
        _state: &mut S,
        _input: &<S as UsesInput>::Input,
    ) -> Result<(), libafl::Error> {
        self.hit = false;
        Ok(())
    }
}

impl Named for CoverageBreakpointObserver {
    fn name(&self) -> &str {
        "CoverageBreakpointObserver"
    }
}
