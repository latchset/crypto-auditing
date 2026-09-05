use crypto_auditing::{
    ContextTracker,
    schema::Schema,
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

const SCHEMA: &'static str = r#"
scope a {
  context a1 {
    context a2 {
      allowed_children b::b1, b::b3;
    }
  }
}

scope b {
  context b1 {
    context b2 {}
  }
  context b3 {}
  context b4 {}
}
        "#;

// This results in the following tree:
//
// ROOT -> C1 ("a::a1") -> C2 ("b::b1") -> C2 ("b::b2")
//   |                  -> C2 ("b::b3")
//   +---> C2 ("b::b4")
//   |
//   +---> C3 ("b::b1")
//
// * an explicit parent-child relationship between C1 and C2 is
//   asserted, before creating C2 ("b::b1")
// * C2 ("b::b4") is rejected to be a child of C1 ("a::a1"), based
//   on the schema, thus becomes a top-level
#[traced_test]
#[test]
fn test_implicit_explicit() {
    let mut tracker = ContextTracker::new(None);
    tracker.set_schema(Schema::parse(SCHEMA).expect("unable to parse schema"));
    // implicit parent-child assertion: C1->C1
    let g1 = EventGroupBuilder::new(C1)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C1))
        .event(name_event("a::a1"))
        .build();
    // implicit parent-child assertion: C1->C1
    let g2 = EventGroupBuilder::new(C1)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C1))
        .event(name_event("a::a2"))
        .build();
    // explicit parent-child assertion: C1->C2 (no name)
    let g3 = EventGroupBuilder::new(C2)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C1))
        .build();
    // implicit parent-child assertion: C2->C2
    let g4 = EventGroupBuilder::new(C2)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C2))
        .event(name_event("b::b1"))
        .build();
    // implicit parent-child assertion: C2->C2
    let g5 = EventGroupBuilder::new(C2)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C2))
        .event(name_event("b::b2"))
        .build();
    // implicit parent-child assertion: C2->C2
    let g6 = EventGroupBuilder::new(C2)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C2))
        .event(name_event("b::b3"))
        .build();
    // implicit parent-child assertion: C2->C2 (forbidden)
    let g7 = EventGroupBuilder::new(C2)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C2))
        .event(name_event("b::b4"))
        .build();
    // implicit parent-child assertion: C3->C3
    let g8 = EventGroupBuilder::new(C3)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C3))
        .event(name_event("b::b1"))
        .build();

    assert_eq!(tracker.handle_event_group(&g1), 1);
    assert_eq!(tracker.handle_event_group(&g2), 0);
    assert_eq!(tracker.handle_event_group(&g3), 0);
    assert_eq!(tracker.handle_event_group(&g4), 0);
    assert_eq!(tracker.handle_event_group(&g5), 0);
    assert_eq!(tracker.handle_event_group(&g6), 0);
    assert_eq!(tracker.handle_event_group(&g7), 1);
    assert_eq!(tracker.handle_event_group(&g8), 1);

    assert_eq!(tracker.root_context_count(), 3);
    assert_eq!(tracker.context_count(), 7);

    assert_eq!(tracker.flush(None).into_iter().count(), 3);

    assert_eq!(tracker.root_context_count(), 0);
    assert_eq!(tracker.context_count(), 0);
}

// This results in the following tree:
//
// ROOT -> C1 ("a::a1") -> C3 ("b::b1") -> C3 ("b::b2")
//
// * an explicit parent-child relationships C1->C2 and C2->C3 are
//   asserted
// * C3 ("b::b1") becomes a child of C1 ("a::a1") because of those
#[traced_test]
#[test]
fn test_implicit_explicit_gaps() {
    let mut tracker = ContextTracker::new(None);
    tracker.set_schema(Schema::parse(SCHEMA).expect("unable to parse schema"));
    // implicit parent-child assertion: C1->C1
    let g1 = EventGroupBuilder::new(C1)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C1))
        .event(name_event("a::a1"))
        .build();
    // implicit parent-child assertion: C1->C1
    let g2 = EventGroupBuilder::new(C1)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C1))
        .event(name_event("a::a2"))
        .build();
    // explicit parent-child assertion: C1->C2 (no name)
    let g3 = EventGroupBuilder::new(C2)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C1))
        .build();
    // explicit parent-child assertion: C2->C3 (no name)
    let g4 = EventGroupBuilder::new(C3)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C2))
        .build();
    // implicit parent-child assertion: C3->C3
    let g5 = EventGroupBuilder::new(C3)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C3))
        .event(name_event("b::b1"))
        .build();
    // implicit parent-child assertion: C3->C3
    let g6 = EventGroupBuilder::new(C3)
        .start(Duration::from_secs(1))
        .end(Duration::from_secs(2))
        .event(context_event(C3))
        .event(name_event("b::b2"))
        .build();

    assert_eq!(tracker.handle_event_group(&g1), 1);
    assert_eq!(tracker.handle_event_group(&g2), 0);
    assert_eq!(tracker.handle_event_group(&g3), 0);
    assert_eq!(tracker.handle_event_group(&g4), 0);
    assert_eq!(tracker.handle_event_group(&g5), 0);
    assert_eq!(tracker.handle_event_group(&g6), 0);

    assert_eq!(tracker.root_context_count(), 1);
    assert_eq!(tracker.context_count(), 4);

    assert_eq!(tracker.flush(None).into_iter().count(), 1);

    assert_eq!(tracker.root_context_count(), 0);
    assert_eq!(tracker.context_count(), 0);
}
