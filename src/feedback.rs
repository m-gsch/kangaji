use std::borrow::Cow;

use libafl::{events::Event, feedbacks::Feedback, observers::ListObserver, state::State};
use libafl_bolts::{
    tuples::{Handle, Handled, MatchNameRef},
    Named,
};

pub struct CoverageFeedback {
    observer_handle: Handle<ListObserver<u8>>,
}

impl<S> Feedback<S> for CoverageFeedback
where
    S: State,
{
    fn is_interesting<EM, OT>(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        _input: &<S>::Input,
        observers: &OT,
        _exit_kind: &libafl::prelude::ExitKind,
    ) -> Result<bool, libafl::Error>
    where
        EM: libafl::prelude::EventFirer<State = S>,
        OT: libafl::prelude::ObserversTuple<S>,
    {
        let observer = observers.get(&self.observer_handle).unwrap();
        let bytes = observer.list();
        if !bytes.is_empty() {
            manager
                .fire(
                    state,
                    Event::CustomBuf {
                        buf: bytes.clone(),
                        tag: "Coverage Hit".to_string(),
                    },
                )
                .unwrap();
            return Ok(true);
        }
        Ok(false)
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
    pub fn new(observer: &ListObserver<u8>) -> Self {
        Self {
            observer_handle: observer.handle(),
        }
    }
}
