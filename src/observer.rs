use crate::errors::HelixError;

pub trait Event<'a, T, E> {
    fn notify(&self, data: &T);
    fn notify_error(&self, error: &E);
    fn subscribe(&mut self, observer: &'a impl Observer<T, E>);
}

pub trait Observer<T, E> {
    fn on_event(&self, data: &T);
    fn on_error(&self, data: &E);
}

pub struct EventImpl<'a, T, E> {
    observers: Vec<&'a dyn Observer<T, E>>,
}

impl<'a, T, E> EventImpl<'a, T, E> {
    pub fn new<'b, A, B>() -> EventImpl<'b, A, B> {
        EventImpl {
            observers: Vec::new(),
        }
    }
}

impl<'a, T, E> Event<'a, T, E> for EventImpl<'a, T, E> {
    fn notify(&self, data: &'_ T) {
        let observers = &self.observers;
        for ele in observers {
            ele.on_event(data);
        }
    }

    fn subscribe(&mut self, observer: &'a impl Observer<T, E>) {
        self.observers.push(observer);
    }

    fn notify_error(&self, error: &E) {
        let observers = &self.observers;
        for ele in observers {
            ele.on_error(error);
        }
    }
}
