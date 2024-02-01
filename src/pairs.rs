use std::cmp::Ord;

/// Small ordered set of pairs.
#[derive(Default)]
pub struct Pairs<T, I = u8>(Vec<(I, T)>);

impl<T: Clone> Clone for Pairs<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T, I> From<Vec<(I, T)>> for Pairs<T, I> {
    fn from(v: Vec<(I, T)>) -> Self {
        Self(v)
    }
}

impl<T, I> From<Pairs<T, I>> for Vec<T> {
    fn from(p: Pairs<T, I>) -> Vec<T> {
        p.0.into_iter().map(|(_, v)| v).collect()
    }
}

impl<T, I: Ord> Pairs<T, I> {
    pub fn with_capacity(size: usize) -> Self {
        Self(Vec::with_capacity(size))
    }

    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn new_with_item(id: I, value: T) -> Self {
        Self(vec![(id, value)])
    }

    pub fn add(mut self, id: I, value: T) -> Self {
        self.push(id, value);
        self
    }

    /// push new pair keeping vector sorted. Min Id at index 0
    pub fn push(&mut self, id: I, value: T) {
        let len = self.0.len();
        let pos = self.0.iter().position(|(p, _)| id < *p).unwrap_or(len);
        self.0.insert(pos, (id, value))
    }

    /// the vector is small, 2-5 items at most.
    pub fn find_pair_or_err<E>(&self, party_id: I, err: E) -> Result<&T, E> {
        self.0
            .iter()
            .find(|(p, _)| *p == party_id)
            .map(|(_, v)| v)
            .ok_or(err)
    }

    /// Find an item by ID, panics if item not found.
    pub fn find_pair(&self, party_id: I) -> &T {
        self.find_pair_or_err(party_id, ())
            .expect("missing item for a party")
    }

    /// Removes an item by given id and return it. Return error if the item not found.
    pub fn pop_pair_or_err<E>(
        &mut self,
        party_id: I,
        err: E,
    ) -> Result<T, E> {
        let pos =
            self.0.iter().position(|(p, _)| *p == party_id).ok_or(err)?;

        Ok(self.0.remove(pos).1)
    }

    /// Removes an item by the given id and returns it. Panics if the item is not found.
    pub fn pop_pair(&mut self, id: I) -> T {
        self.pop_pair_or_err(id, ())
            .expect("missing item for a party")
    }

    pub fn iter(&self) -> impl Iterator<Item = &'_ (I, T)> {
        self.0.iter()
    }
}

impl<T, I: Ord> Pairs<T, I> {
    ///
    pub fn no_dups_by<F>(&self, eq: F) -> bool
    where
        F: Fn(&T, &T) -> bool,
    {
        if !self.0.windows(2).all(|w| w[0].0 < w[1].0) {
            return false;
        }

        // it's O(N^2), but N is expected to by small, like < 10
        for (i, (_, v)) in self.0.iter().enumerate() {
            if i < self.0.len() {
                for (_, p) in &self.0[i + 1..] {
                    if eq(v, p) {
                        return false;
                    }
                }
            }
        }

        true
    }
}

impl<T: Eq, I: Ord> Pairs<T, I> {
    ///
    pub fn no_dups(&self) -> bool {
        self.no_dups_by(|a, b| a.eq(b))
    }
}

impl<T: Clone, I> Pairs<T, I> {
    pub fn remove_ids(&self) -> Vec<T> {
        self.0.iter().map(|(_, v)| v.clone()).collect()
    }
}

impl<T: serde::Serialize, I: serde::Serialize> serde::Serialize
    for Pairs<T, I>
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serde::Serialize::serialize(&self.0, serializer)
    }
}

impl<'de, T: serde::Deserialize<'de>, I: serde::Deserialize<'de>>
    serde::Deserialize<'de> for Pairs<T, I>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        Ok(Pairs(<Vec<(I, T)>>::deserialize(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push() {
        let mut p = Pairs::<u8>::new();

        p.push(10, 10);
        p.push(0, 0);
        p.push(1, 1);

        assert!(p.no_dups());
        assert_eq!(Vec::from(p), vec![0, 1, 10]);
    }

    #[test]
    fn dups() {
        assert! {
            !Pairs::with_capacity(10)
                .add(0, "test")
                .add(1, "test")
                .no_dups()
        };

        assert! {
            !Pairs::with_capacity(10)
                .add(1, "test-1")
                .add(0, "test-0")
                .add(1, "test-2")
                .no_dups()
        };

        assert! {
            Pairs::with_capacity(10)
                .add(0, "test-0")
                .add(1, "test-1")
                .no_dups()
        };
    }
}
