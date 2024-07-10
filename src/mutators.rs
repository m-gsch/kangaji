use libafl::{
    inputs::HasBytesVec,
    mutators::{MutationResult, Mutator},
    state::{HasMaxSize, HasRand},
};
use libafl_bolts::{
    rands::Rand,
    tuples::{tuple_list, tuple_list_type},
    Named,
};

/// Bitflip mutation for inputs with a bytes vector
#[derive(Debug)]
pub struct CharSwapMutator {
    printable: [u8; 97],
}

impl<I, S> Mutator<I, S> for CharSwapMutator
where
    S: HasRand,
    I: HasBytesVec,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, libafl::Error> {
        if input.bytes().is_empty() {
            Ok(MutationResult::Skipped)
        } else {
            let char = state.rand_mut().choose(self.printable);
            let byte = state.rand_mut().choose(input.bytes_mut());
            *byte = char;
            Ok(MutationResult::Mutated)
        }
    }
}

impl Named for CharSwapMutator {
    fn name(&self) -> &str {
        "CharSwapMutator"
    }
}

impl CharSwapMutator {
    #[must_use]
    pub fn new() -> Self {
        let printable_slice = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \t\n!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".as_bytes();
        let mut printable = [0u8; 97];
        printable.copy_from_slice(printable_slice);
        Self { printable }
    }
}

/// Bitflip mutation for inputs with a bytes vector
#[derive(Debug)]
pub struct CharExpandMutator {
    printable: [u8; 97],
}

impl<I, S> Mutator<I, S> for CharExpandMutator
where
    S: HasRand + HasMaxSize,
    I: HasBytesVec,
{
    fn mutate(&mut self, state: &mut S, input: &mut I) -> Result<MutationResult, libafl::Error> {
        let max_size = state.max_size();
        let size = input.bytes().len();
        if size == 0 || size > max_size {
            return Ok(MutationResult::Skipped);
        }
        let size = input.bytes().len();
        let char = state.rand_mut().choose(self.printable);
        input.bytes_mut().resize(size + 1, char);
        Ok(MutationResult::Mutated)
    }
}

impl Named for CharExpandMutator {
    fn name(&self) -> &str {
        "CharExpandMutator"
    }
}

impl CharExpandMutator {
    #[must_use]
    pub fn new() -> Self {
        let printable_slice = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz \t\n!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~".as_bytes();
        let mut printable = [0u8; 97];
        printable.copy_from_slice(printable_slice);
        Self { printable }
    }
}

/// Tuple type of the mutations that compose the Havoc mutator without crossover mutations
pub type TextMutationsType = tuple_list_type!(
    CharSwapMutator,
    CharSwapMutator,
    CharSwapMutator,
    CharExpandMutator
);

pub fn text_mutations() -> TextMutationsType {
    tuple_list!(
        CharSwapMutator::new(),
        CharSwapMutator::new(),
        CharSwapMutator::new(),
        CharExpandMutator::new()
    )
}
