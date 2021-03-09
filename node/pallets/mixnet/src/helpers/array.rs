use crate::Trait;
use sp_std::vec::Vec;

pub fn get_slice<T: Trait, B: Clone>(
    vec: Vec<B>,
    start_position: u64,
    batch_size: u64,
) -> Vec<B> {
    // the # max nr of items in the vector
    let n = vec.len();

    // compute the range end_position
    // if the computed range end_position is larger than n, use n, else, use computed value
    let end_position = start_position as usize + batch_size as usize;
    let end_position = if end_position > n { n } else { end_position };

    // create range
    let range = start_position as usize..end_position;

    // retrieve ciphers in range
    let slice = vec
        .get(range)
        .expect("tried to retrieve ciphers in a range which doesn't exist!");
    slice.to_vec()
}
