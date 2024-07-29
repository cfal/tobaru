use std::ops::Deref;

pub trait HeaderTuple {
    fn append_header_to_string(&self, s: &mut String);
}

impl<S, T> HeaderTuple for (&S, &T)
where
    S: Deref<Target = str>,
    T: Deref<Target = str>,
{
    fn append_header_to_string(&self, s: &mut String) {
        s.push_str(self.0.deref());
        s.push_str(": ");
        s.push_str(self.1.deref());
        s.push_str("\r\n");
    }
}
