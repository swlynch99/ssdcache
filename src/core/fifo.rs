/// Fixed-capacity FIFO, allocated once. Pushing onto a full FIFO is a sizing bug: it
/// returns `Err` so callers can count it, and debug builds assert.
pub struct Fifo<T: Copy> {
    buf: Box<[Option<T>]>,
    head: usize,
    len: usize,
}

impl<T: Copy> Fifo<T> {
    pub fn new(cap: usize) -> Self {
        Fifo { buf: vec![None; cap.max(1)].into_boxed_slice(), head: 0, len: 0 }
    }
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    #[inline]
    pub fn is_full(&self) -> bool {
        self.len == self.buf.len()
    }
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
    #[inline]
    pub fn push(&mut self, v: T) -> Result<(), T> {
        if self.is_full() {
            debug_assert!(false, "Fifo full (cap {})", self.buf.len());
            return Err(v);
        }
        let i = (self.head + self.len) % self.buf.len();
        self.buf[i] = Some(v);
        self.len += 1;
        Ok(())
    }
    #[inline]
    pub fn pop(&mut self) -> Option<T> {
        if self.len == 0 {
            return None;
        }
        let v = self.buf[self.head].take();
        self.head = (self.head + 1) % self.buf.len();
        self.len -= 1;
        v
    }
    #[inline]
    pub fn peek(&self) -> Option<&T> {
        if self.len == 0 { None } else { self.buf[self.head].as_ref() }
    }
    /// Remove the element at logical position `i` (O(len)); used for rare scans.
    pub fn remove_at(&mut self, i: usize) -> Option<T> {
        if i >= self.len {
            return None;
        }
        let cap = self.buf.len();
        let v = self.buf[(self.head + i) % cap].take();
        for j in i..self.len - 1 {
            self.buf[(self.head + j) % cap] = self.buf[(self.head + j + 1) % cap].take();
        }
        self.len -= 1;
        v
    }
    pub fn get(&self, i: usize) -> Option<&T> {
        if i >= self.len { None } else { self.buf[(self.head + i) % self.buf.len()].as_ref() }
    }
}
