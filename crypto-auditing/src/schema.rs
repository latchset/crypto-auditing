// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The crypto-auditing developers.

use pest::Parser;
use pest::iterators::Pair;
use std::fmt::{Display, Formatter};

#[derive(Parser)]
#[grammar = "schema.pest"]
pub struct SchemaParser;

#[derive(Clone, Debug)]
pub enum DataType {
    String,
    Blob,
    Bool,
    UInt8,
    UInt16,
    UInt32,
    UInt64,
    Int8,
    Int16,
    Int32,
    Int64,
}

#[derive(Clone, Debug)]
pub enum Event {
    DataEvent(DataEvent),
    ContextEvent(ContextEvent),
}

#[derive(Clone, Debug)]
pub struct DataEvent {
    pub name: String,
    pub ty: DataType,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Name {
    pub scope: String,
    pub context: String,
}

impl Name {
    pub fn new(scope: &str, context: &str) -> Self {
        Self {
            scope: scope.to_owned(),
            context: context.to_owned(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameParseError {}

impl Display for NameParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "parsing name failed")
    }
}

impl std::error::Error for NameParseError {}

impl TryFrom<&str> for Name {
    type Error = NameParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts: Vec<_> = value.split("::").collect();
        if parts.len() != 2 {
            Err(NameParseError {})
        } else {
            Ok(Self::new(parts[0], parts[1]))
        }
    }
}

#[derive(Clone, Debug)]
pub struct Pattern {
    pub scope: String,
    pub context: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct ContextEvent {
    pub name: String,
    pub events: Vec<Event>,
    pub allowed_children: Vec<Pattern>,
}

#[derive(Debug, Default)]
pub struct Scope {
    pub name: String,
    pub context_events: Vec<ContextEvent>,
}

#[derive(Debug, Default)]
pub struct Schema {
    pub scopes: Vec<Scope>,
}

fn parse_allowed_children(name: &str, pair: Pair<Rule>) -> Vec<Pattern> {
    let mut patterns = Vec::new();

    for inner in pair.into_inner() {
        if inner.as_rule() == Rule::scoped_context_pattern {
            // Traverse in reverse, as scope prefix is optional
            let mut pairs = inner.into_inner().rev();
            let context_pair = pairs.next().expect("context is required");
            let context = match context_pair.as_rule() {
                Rule::ident => Some(context_pair.as_str()),
                Rule::wildcard => None,
                _ => unreachable!(),
            };
            let scope = pairs.next().map(|s| s.as_str()).unwrap_or(name);
            patterns.push(Pattern {
                scope: scope.to_owned(),
                context: context.map(|c| c.to_owned()),
            })
        }
    }
    patterns
}

fn parse_data_event(pair: Pair<Rule>) -> DataEvent {
    let mut pairs = pair.into_inner();
    let name = pairs.next().expect("name is missing");
    let ty = match pairs.next().expect("type is missing").as_str() {
        "string" => DataType::String,
        "blob" => DataType::Blob,
        "bool" => DataType::Bool,
        "uint8" => DataType::UInt8,
        "uint16" => DataType::UInt16,
        "uint32" => DataType::UInt32,
        "uint64" => DataType::UInt64,
        "int8" => DataType::Int8,
        "int16" => DataType::Int16,
        "int32" => DataType::Int32,
        "int64" => DataType::Int64,
        _ => unreachable!(),
    };

    DataEvent {
        name: name.as_str().to_owned(),
        ty,
    }
}

fn parse_context_event(name: &str, pair: Pair<Rule>) -> Vec<ContextEvent> {
    let mut pairs = pair.into_inner();

    let names: Vec<_> = pairs
        .next()
        .expect("names must follow \"context\"")
        .into_inner()
        .map(|name| name.as_str())
        .collect();

    let mut events = Vec::new();
    let mut allowed_children = Vec::new();

    for inner in pairs {
        match inner.as_rule() {
            Rule::data_event => {
                events.push(Event::DataEvent(parse_data_event(inner)));
            }
            Rule::context_event => {
                events.append(
                    &mut parse_context_event(name, inner)
                        .into_iter()
                        .map(|event| Event::ContextEvent(event))
                        .collect(),
                );
            }
            Rule::allowed_children => {
                allowed_children.append(&mut parse_allowed_children(name, inner));
            }
            _ => unreachable!(),
        }
    }
    names
        .into_iter()
        .map(|name| ContextEvent {
            name: name.to_owned(),
            events: events.to_owned(),
            allowed_children: allowed_children.to_owned(),
        })
        .collect()
}

fn parse_scope(pair: Pair<Rule>) -> Scope {
    let mut context_events = Vec::new();

    let mut pairs = pair.into_inner();
    let name = pairs.next().expect("name must follow \"scope\"").as_str();

    for inner in pairs {
        context_events.append(&mut parse_context_event(name, inner));
    }
    Scope {
        name: name.to_owned(),
        context_events,
    }
}

impl Schema {
    /// Parses a schema from string and returns a `Schema`
    pub fn parse(data: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut pairs = SchemaParser::parse(Rule::schema, data)?;
        let schema_pair = pairs.next().expect("schema not found");

        let mut scopes: Vec<Scope> = Vec::new();
        for scope_pair in schema_pair.into_inner() {
            if scope_pair.as_rule() == Rule::scope {
                scopes.push(parse_scope(scope_pair))
            }
        }
        Ok(Self { scopes })
    }

    /// Returns a built-in schema
    pub fn builtin() -> Self {
        let source = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/builtin.schema"));
        Schema::parse(source).expect("unable to read builtin schema")
    }
}
