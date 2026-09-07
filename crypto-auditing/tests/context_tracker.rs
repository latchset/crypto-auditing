use crypto_auditing::{
    ContextTracker,
    types::{ContextId, Event, EventData, EventGroupBuilder},
};
use std::time::Duration;
use tracing_test::traced_test;

const ROOT: ContextId = [0xff; 16];
const C1: ContextId = [1; 16];
const C2: ContextId = [2; 16];
const C3: ContextId = [3; 16];

fn context_event(parent: ContextId) -> Event {
    Event::NewContext {
        parent,
        origin: Default::default(),
        executable: Default::default(),
    }
}

fn name_event(name: &str) -> Event {
    Event::Data {
        key: "name".to_string(),
        value: EventData::String(name.to_string()),
    }
}

#[traced_test]
#[test]
fn test_explicit() {
    let mut tracker = ContextTracker::new(None);
    // explicit parent-child assertion: ROOT->C1
    let g1 = EventGroupBuilder::new(C1)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(ROOT))
        .event(name_event("c1"))
        .build();
    // explicit parent-child assertion: C1->C2
    let g2 = EventGroupBuilder::new(C2)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C1))
        .event(name_event("c2"))
        .build();
    // explicit parent-child assertion: C1->C3
    let g3 = EventGroupBuilder::new(C3)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C1))
        .event(name_event("c3"))
        .build();

    assert_eq!(tracker.handle_event_group(&g1), 1);
    assert_eq!(tracker.handle_event_group(&g2), 0);
    assert_eq!(tracker.handle_event_group(&g3), 0);

    assert_eq!(tracker.root_context_count(), 1);
    assert_eq!(tracker.context_count(), 3);

    assert_eq!(tracker.flush(None).into_iter().count(), 1);

    assert_eq!(tracker.root_context_count(), 0);
    assert_eq!(tracker.context_count(), 0);
}
