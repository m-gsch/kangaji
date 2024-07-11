use std::borrow::Cow;

use libafl::{feedbacks::Feedback, state::State};
use libafl_bolts::{
    tuples::{Handle, Handled, MatchNameRef},
    Named,
};

use crate::observer::CoverageBreakpointObserver;

pub struct CoverageFeedback {
    observer_handle: Handle<CoverageBreakpointObserver>,
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
        let observer = observers.get(&self.observer_handle).unwrap();
        Ok(observer.hit)
    }
}

impl Named for CoverageFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.observer_handle.name()
    }
}

impl CoverageFeedback {
    #[must_use]
    pub fn new(observer: &CoverageBreakpointObserver) -> Self {
        Self {
            observer_handle: observer.handle(),
        }
    }
}
