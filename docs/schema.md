# Event schema

Tracing metadata across supported protocols follows a hierarchical
model consisting of contexts and leaf data events. This document
defines the formal syntax used to describe this structured hierarchy.

## Miscellaneous

Comments follow C-style block syntax. They begin with `/*` and
terminate with `*/`. Comments do not nest and carry no semantic value.

## Scopes

A scope establishes an explicit namespace to logically group related
protocol events.

*Syntax:*

```
scope <name> {
  /* scope declarations */
}
```

where `<name>` is an identifier representing the namespace, and the
enclosed block accepts one or more event declarations.

## Event categories

The schema distinguishes between two event types: Data Events and
Context Events.

Implementation Note: All defined events are optional within emitted
traces. Consuming applications must handle omitted fields gracefully
and not assume event presence.

### Data events

Data events represent leaf key-value pairs assigned to a context.

*Syntax:*

```
<name>: <type>;
```

where `<name>` is the identifier of the data event and `<type>` is the data type of the value.

#### Supported data types

| type   | representation | description                       |
|--------|----------------|-----------------------------------|
| string | string         | a NUL-terminated string           |
| blob   | blob           | a binary blob                     |
| bool   | word           | boolean (0 for false, 1 for true) |
| uint8  | word           | 8-bit unsigned integer            |
| uint16 | word           | 16-bit unsigned integer           |
| uint32 | word           | 32-bit unsigned integer           |
| uint64 | word           | 64-bit unsigned integer           |
| int8   | word           | 8-bit signed integer              |
| int16  | word           | 16-bit signed integer             |
| int32  | word           | 32-bit signed integer             |
| int64  | word           | 64-bit signed integer             |

### Context events

Context events establish structural nodes within the event tree using
the `context` keyword.

*Syntax:*

```
context <name1>[, <name2>...] {
  /* child data, context events, or allowed_children rules */
}
```

A context declaration accepts either a single name or a
comma-separated list of names that share identical block contents. The
enclosed block may contain data events or child context events,
allowing arbitrary nesting.

#### Nesting rules

The context hierarchy defined in the schema is invariant within a
given scope. A child context cannot be moved to the root level or
attached to an undeclared parent context.

*Example:*

```
context c1 {
  s1: string;
  context c2 {
    u1: uint16;
    context c3, c4 {
      i1: int16;
    }
  }
}
```

In this structure, the outermost context `c1` contains scalar `s1` and
nested context `c2`. Context `c2` contains scalar `u1` alongside
context events `c3` and `c4`, both of which enclose data event
`i1`. Runtime events must preserve this precise hierarchy; `c2` cannot
appear at the top level, nor can `c3` be placed directly beneath `c1`.

#### The `allowed_children` directive

By default, only explicitly declared inline child contexts may appear
under a parent context. To allow external top-level context events as
valid runtime children, a context must declare an `allowed_children`
directive.

This directive takes a comma-separated list of pattern declarations
using the syntax `allowed_children <pattern1>[, <pattern2>, ...];`. A
pattern can specify an explicit context name in the current scope
(`<context_name>`), an explicit context in an external scope
(`<scope_name>::<context_name>`), or a wildcard matching all top-level
contexts in a given scope (`<scope_name>::*`). If the scope prefix is
omitted, the current scope is assumed.

For example:

```
scope this {
  context c1 {
    s1: string;
    context c2 {
      u1: uint16;
      allowed_children c3, other::*;
    }
  }
  context c3 {
    i1: int16;
  }
}
```

Here, context `c2` explicitly permits either `this::c3` or any
top-level context defined within the `other` scope to appear as valid
runtime children.

Note that any recursive definitions, either direct or indirect, are
prohibited. In this example, it is an error to write `allowed_children c1;`
instead of `allowed_children c3, other::*;` even if `c1` is also
a top-level.
