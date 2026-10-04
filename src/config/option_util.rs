use serde::Deserialize;

#[derive(Default, Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum NoneOrOne<T> {
    #[serde(skip_deserializing)]
    #[default]
    Unspecified,
    None,
    One(T),
}

#[derive(Default, Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum NoneOrSome<T> {
    #[serde(skip_deserializing)]
    #[default]
    Unspecified,
    None,
    One(T),
    Some(Vec<T>),
}

impl<T> NoneOrSome<T> {
    pub fn is_empty(&self) -> bool {
        match self {
            NoneOrSome::Unspecified => true,
            NoneOrSome::None => true,
            NoneOrSome::One(_) => false,
            NoneOrSome::Some(v) => v.is_empty(),
        }
    }

    pub fn into_vec(self) -> Vec<T> {
        match self {
            NoneOrSome::Unspecified | NoneOrSome::None => vec![],
            NoneOrSome::One(item) => vec![item],
            NoneOrSome::Some(v) => v,
        }
    }

    pub fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a T> + Send + 'a>
    where
        T: Sync,
    {
        match self {
            NoneOrSome::Unspecified | NoneOrSome::None => Box::new(std::iter::empty()),
            NoneOrSome::One(item) => Box::new(SingleItemIter(Some(item))),
            NoneOrSome::Some(v) => Box::new(v.iter()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum OneOrSome<T> {
    One(T),
    #[serde(deserialize_with = "validate_non_empty")]
    Some(Vec<T>),
}

fn validate_non_empty<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: serde::de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    let value = Vec::deserialize(d)?;
    if value.is_empty() {
        return Err(serde::de::Error::invalid_value(
            serde::de::Unexpected::Other("empty"),
            &"need at least one element",
        ));
    }
    Ok(value)
}

impl<T> OneOrSome<T> {
    pub fn into_vec(self) -> Vec<T> {
        match self {
            OneOrSome::One(item) => vec![item],
            OneOrSome::Some(v) => v,
        }
    }

    pub fn into_iter(self) -> Box<dyn Iterator<Item = T> + Send>
    where
        T: Send + 'static,
    {
        match self {
            OneOrSome::One(item) => Box::new(SingleItemIter(Some(item))),
            OneOrSome::Some(v) => Box::new(v.into_iter()),
        }
    }

    pub fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = &'a T> + Send + 'a>
    where
        T: Sync,
    {
        match self {
            OneOrSome::One(item) => Box::new(SingleItemIter(Some(item))),
            OneOrSome::Some(v) => Box::new(v.iter()),
        }
    }

    pub fn iter_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &'a mut T> + Send + 'a>
    where
        T: Send,
    {
        match self {
            OneOrSome::One(ref mut item) => Box::new(SingleItemIter(Some(item))),
            OneOrSome::Some(v) => Box::new(v.iter_mut()),
        }
    }
}

struct SingleItemIter<T>(Option<T>);

impl<T> Iterator for SingleItemIter<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.take()
    }
}
