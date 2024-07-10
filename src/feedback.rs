use libafl::{feedbacks::Feedback, state::State};
use libafl_bolts::Named;

use crate::observer::CoverageBreakpointObserver;

pub struct CoverageFeedback {
    name: String,
    observer_name: String,
}

impl<S> Feedback<S> for CoverageFeedback
where
    S: State,
{
    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &<S>::Input,
        observers: &OT,
        _exit_kind: &libafl::prelude::ExitKind,
    ) -> Result<bool, libafl::Error>
    where
        EM: libafl::prelude::EventFirer<State = S>,
        OT: libafl::prelude::ObserversTuple<S>,
    {
        let observer = observers
            .match_name::<CoverageBreakpointObserver>(&self.observer_name)
            .unwrap();
        Ok(observer.hit)
    }
}

impl Named for CoverageFeedback {
    #[inline]
    fn name(&self) -> &str {
        self.name.as_str()
    }
}

impl CoverageFeedback {
    #[must_use]
    pub fn new(observer: &CoverageBreakpointObserver) -> Self {
        Self {
            name: observer.name().to_string(),
            observer_name: observer.name().to_string(),
        }
    }
}
