# Event schema

Tracing metadata across supported protocols follows a hierarchical
model consisting of contexts and leaf data events. This document
defines the formal syntax used to describe this hierarchy.

## Miscellaneous

Comments use C-style block syntax: they begin with `/*` and end with
`*/`. Comments do not nest and have no semantic meaning.

## Scopes

A scope defines a namespace that groups related protocol events.

*Syntax:*

```
scope <name> {
  /* scope declarations */
}
```

where `<name>` is an identifier naming the namespace, and the enclosed
block contains one or more event declarations.

## Event categories

The schema distinguishes between two kinds of events: data events and
context events.

Implementation note: all defined events are optional in emitted
traces. Consumers must handle omitted events gracefully and must not
assume that any event is present.

### Data events

Data events are leaf key-value pairs attached to a context.

*Syntax:*

```
<name>: <type>;
```

where `<name>` is the identifier of the data event and `<type>` is the
type of its value.

#### Supported data types

The *representation* column shows how values of each type are carried
in probe events (see [USDT probe points](probe-points.md)).

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

Context events define structural nodes in the event tree using the
`context` keyword.

*Syntax:*

```
context <name1>[, <name2>...] {
  /* child data, context events, or allowed_children rules */
}
```

A context declaration takes either a single name or a comma-separated
list of names that share the same block contents. The block may
contain data events, child context events, and `allowed_children`
directives, allowing arbitrary nesting.

#### Nesting rules

The context hierarchy defined in the schema is fixed within a given
scope: a child context cannot be moved to the root level or attached
to a parent context other than the one in which it is declared.

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

In this structure, the outermost context `c1` contains the data event
`s1` and the nested context `c2`. Context `c2` contains the data event
`u1` and the contexts `c3` and `c4`, both of which contain the data
event `i1`. Runtime events must follow this exact hierarchy: `c2`
cannot appear at the top level, nor can `c3` appear directly under
`c1`.

#### The `allowed_children` directive

By default, only child contexts declared inline may appear under a
parent context. To also accept top-level contexts declared elsewhere
as runtime children, a context must declare an `allowed_children`
directive.

The directive takes a comma-separated list of patterns, using the
syntax `allowed_children <pattern1>[, <pattern2>, ...];`. A pattern
can be a context name in the current scope (`<context_name>`), a
context in another scope (`<scope_name>::<context_name>`), or a
wildcard matching all top-level contexts in a given scope
(`<scope_name>::*`). If the scope prefix is omitted, the current scope
is assumed.

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

Here, context `c2` permits `this::c3` and any top-level context
defined in the `other` scope to appear as its runtime children.

Note that recursive definitions, whether direct or indirect, are
prohibited. In this example, it would be an error to write
`allowed_children c1;` instead of `allowed_children c3, other::*;`,
even though `c1` is also a top-level context.
