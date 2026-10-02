mod discovery;
mod lifecycle;
mod paths;
mod punch;
mod recv;
mod send;
mod terminate;
mod tls;

use crate::Paths;

impl Paths {
    fn retire_all(&self) {
        self.phase().terminator().terminate();
        for path in self.snapshot() {
            self.remove(&path);
        }
    }
}
