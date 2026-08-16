//! SCIP protobuf instrumentation without a generated schema dependency.
//!
//! The adapter accepts the stable wire representation emitted by SCIP indexers,
//! decodes only the graph-bearing fields, and projects them through the graph
//! contract. Unknown protobuf fields are skipped, so newer indexers remain
//! readable while malformed or excessively large input is rejected.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_graph_api::{
    CoordinateKind, GraphCoordinate, GraphCoverage, GraphEdge, GraphFreshness, GraphNode,
    GraphQuery, GraphQueryKind, GraphQueryResult, GraphQueryStatus, GraphRevision,
};
use thiserror::Error;

pub const SCIP_INSTRUMENT: &str = "eliot.instrument.scip";
pub const MAX_SCIP_BYTES: usize = 256 * 1024 * 1024;
const MAX_FIELD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScipIndex {
    pub documents: Vec<ScipDocument>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScipDocument {
    pub relative_path: String,
    pub symbols: Vec<ScipSymbol>,
    pub occurrences: Vec<ScipOccurrence>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScipSymbol {
    pub symbol: String,
    pub kind: u64,
    pub display_name: Option<String>,
    pub enclosing_symbol: Option<String>,
    pub relationships: Vec<ScipRelationship>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "SCIP relationship flags are the established public wire projection"
)]
pub struct ScipRelationship {
    pub symbol: String,
    pub definition: bool,
    pub reference: bool,
    pub implementation: bool,
    pub type_definition: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScipOccurrence {
    pub symbol: String,
    pub line: u32,
    pub column: u32,
    pub roles: u64,
}

impl ScipIndex {
    pub fn decode(bytes: &[u8]) -> Result<Self, ScipError> {
        if bytes.len() > MAX_SCIP_BYTES {
            return Err(ScipError::InputTooLarge);
        }
        let mut reader = Reader::new(bytes);
        let mut documents = Vec::new();
        while let Some((field, wire)) = reader.next()? {
            match (field, wire) {
                (2, 2) => documents.push(decode_document(reader.bytes()?)?),
                _ => reader.skip(wire)?,
            }
        }
        Ok(Self { documents })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "projection order is deterministic and parsing-dependent; keeping it contiguous preserves graph precedence"
    )]
    pub fn graph_result(
        &self,
        query: &GraphQuery,
        revision: GraphRevision,
    ) -> Result<GraphQueryResult, ScipError> {
        query
            .validate()
            .map_err(|e| ScipError::Graph(e.to_string()))?;
        let package = query.scope.clone();
        let mut nodes = BTreeMap::<GraphCoordinate, GraphNode>::new();
        let mut edges = BTreeSet::<GraphEdgeKey>::new();
        for document in &self.documents {
            let symbol_map: BTreeMap<_, _> = document
                .symbols
                .iter()
                .map(|symbol| (symbol.symbol.as_str(), symbol))
                .collect();
            for occurrence in &document.occurrences {
                if let Some(symbol) = symbol_map.get(occurrence.symbol.as_str()) {
                    let coordinate = GraphCoordinate {
                        kind: CoordinateKind::Span,
                        package: package.clone(),
                        path: Some(document.relative_path.clone()),
                        symbol: Some(occurrence.symbol.clone()),
                        line: Some(occurrence.line.saturating_add(1)),
                        column: Some(occurrence.column.saturating_add(1)),
                    };
                    nodes
                        .entry(coordinate.clone())
                        .or_insert_with(|| GraphNode {
                            coordinate,
                            kind: format!("scip_symbol_{}", symbol.kind),
                            label: symbol.display_name.clone(),
                        });
                    for relationship in &symbol.relationships {
                        let to = GraphCoordinate {
                            kind: CoordinateKind::Symbol,
                            package: package.clone(),
                            path: None,
                            symbol: Some(relationship.symbol.clone()),
                            line: None,
                            column: None,
                        };
                        edges.insert(GraphEdgeKey {
                            from: nodes
                                .keys()
                                .find(|key| {
                                    key.symbol.as_deref() == Some(occurrence.symbol.as_str())
                                        && key.path.as_deref()
                                            == Some(document.relative_path.as_str())
                                })
                                .cloned()
                                .unwrap_or_else(|| GraphCoordinate {
                                    kind: CoordinateKind::Symbol,
                                    package: package.clone(),
                                    path: None,
                                    symbol: Some(occurrence.symbol.clone()),
                                    line: None,
                                    column: None,
                                }),
                            to,
                            relation: relationship.relation(),
                        });
                    }
                }
            }
        }
        let matches = |coordinate: &GraphCoordinate| {
            let expression = &query.expression;
            let text_match = coordinate
                .path
                .as_deref()
                .is_some_and(|p| p.contains(expression))
                || coordinate
                    .symbol
                    .as_deref()
                    .is_some_and(|s| s.contains(expression));
            match query.kind {
                GraphQueryKind::Search => text_match,
                GraphQueryKind::Exact => {
                    coordinate.symbol.as_deref() == Some(expression)
                        || coordinate.path.as_deref() == Some(expression)
                }
                GraphQueryKind::Impact => query
                    .root
                    .as_ref()
                    .is_some_and(|root| coordinate.symbol == root.symbol),
            }
        };
        let selected: BTreeSet<_> = nodes.keys().filter(|node| matches(node)).cloned().collect();
        let result_nodes: Vec<_> = nodes
            .into_iter()
            .filter_map(|(key, value)| selected.contains(&key).then_some(value))
            .collect();
        let result_edges: Vec<_> = edges
            .into_iter()
            .filter_map(|edge| {
                (selected.contains(&edge.from) || selected.contains(&edge.to)).then_some(
                    GraphEdge {
                        from: edge.from,
                        to: edge.to,
                        relation: edge.relation,
                    },
                )
            })
            .collect();
        let status = if result_nodes.is_empty() && result_edges.is_empty() {
            GraphQueryStatus::NotFound
        } else {
            GraphQueryStatus::Found
        };
        let absence = if matches!(status, GraphQueryStatus::NotFound) {
            Some(eliot_graph_api::AbsenceEvidence {
                checked_scope: query.scope.clone(),
                inspected_records: self
                    .documents
                    .iter()
                    .map(|d| d.occurrences.len() as u64)
                    .sum::<u64>()
                    .max(1),
                query_digest: GraphQueryResult::query_digest(query)
                    .map_err(|e| ScipError::Graph(e.to_string()))?,
                checked_revision: revision,
            })
        } else {
            None
        };
        Ok(GraphQueryResult {
            query_id: query.query_id.clone(),
            status,
            revision,
            freshness: GraphFreshness::Current,
            coverage: GraphCoverage::Complete,
            nodes: result_nodes,
            edges: result_edges,
            absence,
            diagnostics: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct GraphEdgeKey {
    from: GraphCoordinate,
    to: GraphCoordinate,
    relation: String,
}

impl ScipRelationship {
    fn relation(&self) -> String {
        (if self.implementation {
            "implements"
        } else if self.type_definition {
            "type_defines"
        } else if self.definition {
            "defines"
        } else if self.reference {
            "references"
        } else {
            "related"
        })
        .to_owned()
    }
}

fn decode_document(bytes: &[u8]) -> Result<ScipDocument, ScipError> {
    let mut r = Reader::new(bytes);
    let mut path = None;
    let mut symbols = Vec::new();
    let mut occurrences = Vec::new();
    while let Some((field, wire)) = r.next()? {
        match (field, wire) {
            (1, 2) => path = Some(r.text()?),
            (3, 2) => symbols.push(decode_symbol(r.bytes()?)?),
            (4, 2) => occurrences.push(decode_occurrence(r.bytes()?)?),
            _ => r.skip(wire)?,
        }
    }
    let relative_path = path.ok_or(ScipError::MissingField("document.relative_path"))?;
    if relative_path.is_empty() || relative_path.chars().any(char::is_control) {
        return Err(ScipError::InvalidText);
    }
    Ok(ScipDocument {
        relative_path,
        symbols,
        occurrences,
    })
}

fn decode_symbol(bytes: &[u8]) -> Result<ScipSymbol, ScipError> {
    let mut r = Reader::new(bytes);
    let mut symbol = None;
    let mut kind = 0;
    let mut display_name = None;
    let mut enclosing_symbol = None;
    let mut relationships = Vec::new();
    while let Some((field, wire)) = r.next()? {
        match (field, wire) {
            (1, 2) => symbol = Some(r.text()?),
            (2, 0) => kind = r.varint()?,
            (3, 2) => display_name = Some(r.text()?),
            (6, 2) => enclosing_symbol = Some(r.text()?),
            (7, 2) => relationships.push(decode_relationship(r.bytes()?)?),
            _ => r.skip(wire)?,
        }
    }
    Ok(ScipSymbol {
        symbol: symbol.ok_or(ScipError::MissingField("symbol.symbol"))?,
        kind,
        display_name,
        enclosing_symbol,
        relationships,
    })
}

fn decode_relationship(bytes: &[u8]) -> Result<ScipRelationship, ScipError> {
    let mut r = Reader::new(bytes);
    let mut symbol = None;
    let mut flags = [false; 4];
    while let Some((field, wire)) = r.next()? {
        match (field, wire) {
            (1, 2) => symbol = Some(r.text()?),
            (2..=5, 0) => {
                let index = usize::try_from(field - 2).map_err(|_| ScipError::InvalidWire)?;
                flags[index] = r.varint()? != 0;
            }
            _ => r.skip(wire)?,
        }
    }
    Ok(ScipRelationship {
        symbol: symbol.ok_or(ScipError::MissingField("relationship.symbol"))?,
        definition: flags[0],
        reference: flags[1],
        implementation: flags[2],
        type_definition: flags[3],
    })
}

fn decode_occurrence(bytes: &[u8]) -> Result<ScipOccurrence, ScipError> {
    let mut r = Reader::new(bytes);
    let mut range = Vec::new();
    let mut symbol = None;
    let mut roles = 0;
    while let Some((field, wire)) = r.next()? {
        match (field, wire) {
            (1, 2) => {
                let packed = r.bytes()?;
                let mut p = Reader::new(packed);
                while !p.done() {
                    range.push(p.varint()?);
                }
            }
            (1, 0) => range.push(r.varint()?),
            (2, 2) => symbol = Some(r.text()?),
            (3, 0) => roles = r.varint()?,
            _ => r.skip(wire)?,
        }
    }
    if range.len() < 2 {
        return Err(ScipError::InvalidRange);
    }
    let line = u32::try_from(range[0]).map_err(|_| ScipError::InvalidRange)?;
    let column = u32::try_from(range[1]).map_err(|_| ScipError::InvalidRange)?;
    Ok(ScipOccurrence {
        symbol: symbol.ok_or(ScipError::MissingField("occurrence.symbol"))?,
        line,
        column,
        roles,
    })
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn done(&self) -> bool {
        self.pos == self.bytes.len()
    }
    fn next(&mut self) -> Result<Option<(u32, u8)>, ScipError> {
        if self.done() {
            return Ok(None);
        }
        let key = self.varint()?;
        let field = u32::try_from(key >> 3).map_err(|_| ScipError::InvalidWire)?;
        let wire = (key & 7) as u8;
        if field == 0 || wire == 4 {
            return Err(ScipError::InvalidWire);
        }
        Ok(Some((field, wire)))
    }
    fn varint(&mut self) -> Result<u64, ScipError> {
        let mut value = 0;
        for shift in (0..70).step_by(7) {
            let byte = *self.bytes.get(self.pos).ok_or(ScipError::Truncated)?;
            self.pos += 1;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(ScipError::VarintOverflow)
    }
    fn bytes(&mut self) -> Result<&'a [u8], ScipError> {
        let len = usize::try_from(self.varint()?).map_err(|_| ScipError::FieldTooLarge)?;
        if len > MAX_FIELD_BYTES {
            return Err(ScipError::FieldTooLarge);
        }
        let end = self.pos.checked_add(len).ok_or(ScipError::Truncated)?;
        let result = self.bytes.get(self.pos..end).ok_or(ScipError::Truncated)?;
        self.pos = end;
        Ok(result)
    }
    fn text(&mut self) -> Result<String, ScipError> {
        let value = std::str::from_utf8(self.bytes()?).map_err(|_| ScipError::InvalidUtf8)?;
        if value.chars().any(char::is_control) {
            return Err(ScipError::InvalidText);
        }
        Ok(value.to_owned())
    }
    fn skip(&mut self, wire: u8) -> Result<(), ScipError> {
        match wire {
            0 => {
                self.varint()?;
                Ok(())
            }
            1 => self.take(8).map(|_| ()),
            2 => self.bytes().map(|_| ()),
            5 => self.take(4).map(|_| ()),
            _ => Err(ScipError::InvalidWire),
        }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8], ScipError> {
        let end = self.pos.checked_add(len).ok_or(ScipError::Truncated)?;
        let out = self.bytes.get(self.pos..end).ok_or(ScipError::Truncated)?;
        self.pos = end;
        Ok(out)
    }
}

#[derive(Debug, Error)]
pub enum ScipError {
    #[error("SCIP input exceeds the bounded capture limit")]
    InputTooLarge,
    #[error("SCIP field exceeds the bounded field limit")]
    FieldTooLarge,
    #[error("SCIP protobuf is truncated")]
    Truncated,
    #[error("SCIP protobuf varint overflowed")]
    VarintOverflow,
    #[error("SCIP protobuf contains an invalid wire value")]
    InvalidWire,
    #[error("SCIP protobuf contains invalid UTF-8")]
    InvalidUtf8,
    #[error("SCIP text contains a control character")]
    InvalidText,
    #[error("SCIP record is missing {0}")]
    MissingField(&'static str),
    #[error("SCIP occurrence has no usable source range")]
    InvalidRange,
    #[error("graph contract rejected SCIP projection: {0}")]
    Graph(String),
}

#[cfg(test)]
mod tests {
    use super::decode_relationship;

    #[test]
    fn relationship_boolean_fields_require_varint_wire_type() -> Result<(), super::ScipError> {
        let relationship = decode_relationship(&[
            0x0a, 0x01, b'x', // symbol
            0x10, 0x01, // definition
            0x18, 0x00, // reference
            0x20, 0x01, // implementation
            0x28, 0x01, // type_definition
        ])?;

        assert_eq!(relationship.symbol, "x");
        assert!(relationship.definition);
        assert!(!relationship.reference);
        assert!(relationship.implementation);
        assert!(relationship.type_definition);
        Ok(())
    }
}
