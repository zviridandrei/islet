use super::vm::VM;

use alloc::sync::{Arc, Weak};
use spin::Mutex;

extern crate alloc;

pub trait Context {
    fn new() -> Self
    where
        Self: Sized;
    unsafe fn set_current(vcpu: &mut VCPU<Self>)
    where
        Self: Sized;
}

#[repr(C)]
#[derive(Debug)]
pub struct VCPU<T: Context> {
    pub context: T,
    pub vm: Weak<Mutex<VM<T>>>, // VM struct the VCPU belongs to
    pub state: State,
    pub pcpu: Option<usize>,
}

impl<T: Context + Default> VCPU<T> {
    pub fn new(vm: Weak<Mutex<VM<T>>>) -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            vm: vm,
            state: State::Ready,
            context: T::new(),
            pcpu: None,
        }))
    }

    pub fn set_current(&mut self) {
        unsafe { T::set_current(self) }
    }
}

impl<T: Context> Drop for VCPU<T> {
    fn drop(&mut self) {
        //TODO unset current if the current is this
    }
}

#[derive(Debug)]
pub enum State {
    Ready,
    Running,
    Blocked,
}