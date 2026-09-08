//! Borrowed checked preflight before owner validation, cloning or hashing.

use std::{
    fmt,
    io::{self, Write},
};

use serde::{Serialize, ser};

use crate::{
    ActivationAssessmentError,
    assessment::AssessmentInput,
    contracts::{
        AssessmentPolicy, MAX_DIMENSIONS, MAX_INPUT_BYTES, MAX_METRICS, MAX_REFERENCES, MAX_STAGES,
    },
};

const MAX_LEAF_BYTES: usize = 1024 * 1024;
const MAX_COLLECTION_ITEMS: usize = 65_536;
const MAX_DEPTH: usize = 128;

/// Borrowed serialization of every retained input field.
#[derive(Serialize)]
pub(crate) struct BoundedInput<'a> {
    pub recipe: &'a eliot_learning_contracts::LearningStateViewRecipe,
    pub binding: &'a eliot_learning_contracts::ContractBinding,
    pub target: &'a eliot_learning_contracts::TargetId,
    pub view: &'a eliot_learning_contracts::CampaignLearningStateView,
    pub delta: &'a eliot_learning_contracts::AttemptLearningDeltaCandidate,
    pub overlay: &'a eliot_learning_contracts::CampaignHarnessOverlayCandidate,
    pub policy: &'a AssessmentPolicy,
    pub activation_id: Option<&'a eliot_contracts::ArtifactId>,
    pub admission_receipt: Option<&'a eliot_contracts::ArtifactId>,
    pub activation_request_receipt: Option<&'a eliot_contracts::ArtifactId>,
    pub assessment_receipt: Option<&'a eliot_contracts::ArtifactId>,
    pub stages: &'a [eliot_learning_contracts::StageObservation],
    pub metrics: &'a [eliot_learning_contracts::MetricObservation],
    pub attrition: &'a [eliot_contracts::ArtifactId],
    pub confounders: &'a [eliot_contracts::ArtifactId],
    pub independent_evaluator_receipt: Option<&'a eliot_contracts::ArtifactId>,
    pub dimensions: &'a [eliot_learning_contracts::DimensionAssessment],
    pub external_review_refs: &'a [eliot_contracts::ArtifactId],
}

struct Counter {
    count: usize,
    limit: usize,
}

impl Write for Counter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count = self
            .count
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("serialized counter overflow"))?;
        if self.count > self.limit {
            return Err(io::Error::other("serialized bound"));
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
struct StructureError;

impl fmt::Display for StructureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded structural preflight failed")
    }
}
impl std::error::Error for StructureError {}
impl ser::Error for StructureError {
    fn custom<T: fmt::Display>(_message: T) -> Self {
        Self
    }
}

struct State {
    bytes: usize,
    limit: usize,
    depth: usize,
}

impl State {
    fn add(&mut self, amount: usize) -> Result<(), StructureError> {
        self.bytes = self.bytes.checked_add(amount).ok_or(StructureError)?;
        if self.bytes > self.limit {
            return Err(StructureError);
        }
        Ok(())
    }
    fn text(&mut self, value: &str) -> Result<(), StructureError> {
        if value.len() > MAX_LEAF_BYTES {
            return Err(StructureError);
        }
        self.add(value.len())
    }
    fn enter(&mut self) -> Result<(), StructureError> {
        self.depth = self.depth.checked_add(1).ok_or(StructureError)?;
        if self.depth > MAX_DEPTH {
            return Err(StructureError);
        }
        Ok(())
    }
    fn leave(&mut self) {
        if self.depth > 0 {
            self.depth -= 1;
        }
    }
    fn items(&mut self, len: usize) -> Result<(), StructureError> {
        if len > MAX_COLLECTION_ITEMS {
            return Err(StructureError);
        }
        self.add(len)
    }
}

struct StructuralSerializer<'a> {
    state: &'a mut State,
}
struct Compound<'a> {
    state: &'a mut State,
    items: usize,
}

impl Compound<'_> {
    fn item<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), StructureError> {
        self.items = self.items.checked_add(1).ok_or(StructureError)?;
        if self.items > MAX_COLLECTION_ITEMS {
            return Err(StructureError);
        }
        value.serialize(StructuralSerializer { state: self.state })
    }
    fn finish(self) {
        self.state.leave();
    }
}

impl<'a> ser::Serializer for StructuralSerializer<'a> {
    type Ok = ();
    type Error = StructureError;
    type SerializeSeq = Compound<'a>;
    type SerializeTuple = Compound<'a>;
    type SerializeTupleStruct = Compound<'a>;
    type SerializeTupleVariant = Compound<'a>;
    type SerializeMap = Compound<'a>;
    type SerializeStruct = Compound<'a>;
    type SerializeStructVariant = Compound<'a>;

    fn serialize_bool(self, _: bool) -> Result<(), Self::Error> {
        self.state.add(1)
    }
    fn serialize_i8(self, _: i8) -> Result<(), Self::Error> {
        self.state.add(1)
    }
    fn serialize_i16(self, _: i16) -> Result<(), Self::Error> {
        self.state.add(2)
    }
    fn serialize_i32(self, _: i32) -> Result<(), Self::Error> {
        self.state.add(4)
    }
    fn serialize_i64(self, _: i64) -> Result<(), Self::Error> {
        self.state.add(8)
    }
    fn serialize_i128(self, _: i128) -> Result<(), Self::Error> {
        self.state.add(16)
    }
    fn serialize_u8(self, _: u8) -> Result<(), Self::Error> {
        self.state.add(1)
    }
    fn serialize_u16(self, _: u16) -> Result<(), Self::Error> {
        self.state.add(2)
    }
    fn serialize_u32(self, _: u32) -> Result<(), Self::Error> {
        self.state.add(4)
    }
    fn serialize_u64(self, _: u64) -> Result<(), Self::Error> {
        self.state.add(8)
    }
    fn serialize_u128(self, _: u128) -> Result<(), Self::Error> {
        self.state.add(16)
    }
    fn serialize_f32(self, _: f32) -> Result<(), Self::Error> {
        self.state.add(4)
    }
    fn serialize_f64(self, _: f64) -> Result<(), Self::Error> {
        self.state.add(8)
    }
    fn serialize_char(self, _: char) -> Result<(), Self::Error> {
        self.state.add(4)
    }
    fn serialize_str(self, value: &str) -> Result<(), Self::Error> {
        self.state.text(value)
    }
    fn serialize_bytes(self, value: &[u8]) -> Result<(), Self::Error> {
        if value.len() > MAX_LEAF_BYTES {
            return Err(StructureError);
        }
        self.state.add(value.len())
    }
    fn serialize_none(self) -> Result<(), Self::Error> {
        Ok(())
    }
    fn serialize_some<T: ?Sized + Serialize>(self, value: &T) -> Result<(), Self::Error> {
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), Self::Error> {
        Ok(())
    }
    fn serialize_unit_struct(self, name: &'static str) -> Result<(), Self::Error> {
        self.state.text(name)
    }
    fn serialize_unit_variant(
        self,
        name: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<(), Self::Error> {
        self.state.text(name)?;
        self.state.text(variant)
    }
    fn serialize_newtype_struct<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.state.text(name)?;
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: ?Sized + Serialize>(
        self,
        name: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.state.text(name)?;
        self.state.text(variant)?;
        value.serialize(self)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        self.state.enter()?;
        if let Some(len) = len {
            self.state.items(len)?;
        }
        Ok(Compound {
            state: self.state,
            items: 0,
        })
    }
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        self.state.text(name)?;
        self.serialize_seq(Some(len))
    }
    fn serialize_tuple_variant(
        self,
        name: &'static str,
        _: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.state.text(name)?;
        self.state.text(variant)?;
        self.serialize_seq(Some(len))
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        self.state.enter()?;
        if let Some(len) = len {
            self.state.items(len)?;
        }
        Ok(Compound {
            state: self.state,
            items: 0,
        })
    }
    fn serialize_struct(
        self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStruct, Self::Error> {
        self.state.text(name)?;
        self.state.enter()?;
        self.state.items(len)?;
        Ok(Compound {
            state: self.state,
            items: 0,
        })
    }
    fn serialize_struct_variant(
        self,
        name: &'static str,
        _: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.state.text(name)?;
        self.state.text(variant)?;
        self.state.enter()?;
        self.state.items(len)?;
        Ok(Compound {
            state: self.state,
            items: 0,
        })
    }
}

impl ser::SerializeSeq for Compound<'_> {
    type Ok = ();
    type Error = StructureError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.item(value)
    }
    fn end(self) -> Result<(), Self::Error> {
        self.finish();
        Ok(())
    }
}
impl ser::SerializeTuple for Compound<'_> {
    type Ok = ();
    type Error = StructureError;
    fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.item(value)
    }
    fn end(self) -> Result<(), Self::Error> {
        self.finish();
        Ok(())
    }
}
impl ser::SerializeTupleStruct for Compound<'_> {
    type Ok = ();
    type Error = StructureError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.item(value)
    }
    fn end(self) -> Result<(), Self::Error> {
        self.finish();
        Ok(())
    }
}
impl ser::SerializeTupleVariant for Compound<'_> {
    type Ok = ();
    type Error = StructureError;
    fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.item(value)
    }
    fn end(self) -> Result<(), Self::Error> {
        self.finish();
        Ok(())
    }
}
impl ser::SerializeMap for Compound<'_> {
    type Ok = ();
    type Error = StructureError;
    fn serialize_key<T: ?Sized + Serialize>(&mut self, key: &T) -> Result<(), Self::Error> {
        self.item(key)
    }
    fn serialize_value<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<(), Self::Error> {
        self.item(value)
    }
    fn end(self) -> Result<(), Self::Error> {
        self.finish();
        Ok(())
    }
}
impl ser::SerializeStruct for Compound<'_> {
    type Ok = ();
    type Error = StructureError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.state.text(key)?;
        self.item(value)
    }
    fn end(self) -> Result<(), Self::Error> {
        self.finish();
        Ok(())
    }
}
impl ser::SerializeStructVariant for Compound<'_> {
    type Ok = ();
    type Error = StructureError;
    fn serialize_field<T: ?Sized + Serialize>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), Self::Error> {
        self.state.text(key)?;
        self.item(value)
    }
    fn end(self) -> Result<(), Self::Error> {
        self.finish();
        Ok(())
    }
}

fn structural_preflight<T: ?Sized + Serialize>(
    value: &T,
    limit: usize,
) -> Result<(), ActivationAssessmentError> {
    let mut state = State {
        bytes: 0,
        limit,
        depth: 0,
    };
    value
        .serialize(StructuralSerializer { state: &mut state })
        .map_err(|_| ActivationAssessmentError::Bound { field: "structure" })
}

/// Count a serializable value without allocating a byte buffer.
pub(crate) fn bounded_serialized_len<T: Serialize>(
    value: &T,
    limit: usize,
    field: &'static str,
) -> Result<usize, ActivationAssessmentError> {
    structural_preflight(value, limit).map_err(|_| ActivationAssessmentError::Bound { field })?;
    let mut counter = Counter { count: 0, limit };
    serde_json::to_writer(&mut counter, value)
        .map_err(|_| ActivationAssessmentError::Bound { field })?;
    Ok(counter.count)
}

/// Check operation-level cardinalities and complete retained-input accounting.
pub(crate) fn preflight(input: &AssessmentInput<'_>) -> Result<(), ActivationAssessmentError> {
    if input.stages.len() > MAX_STAGES {
        return Err(ActivationAssessmentError::Bound { field: "stages" });
    }
    if input.dimensions.len() > MAX_DIMENSIONS {
        return Err(ActivationAssessmentError::Bound {
            field: "dimensions",
        });
    }
    if input.metrics.len() > MAX_METRICS {
        return Err(ActivationAssessmentError::Bound { field: "metrics" });
    }
    let references = input
        .attrition
        .len()
        .checked_add(input.confounders.len())
        .and_then(|value| value.checked_add(input.external_review_refs.len()))
        .ok_or(ActivationAssessmentError::Bound {
            field: "references",
        })?;
    if references > MAX_REFERENCES {
        return Err(ActivationAssessmentError::Bound {
            field: "references",
        });
    }
    input
        .policy
        .validate_shape()
        .map_err(|field| ActivationAssessmentError::Bound { field })?;
    let bounded = BoundedInput {
        recipe: input.recipe,
        binding: input.binding,
        target: input.target,
        view: input.view,
        delta: input.delta,
        overlay: input.overlay,
        policy: input.policy,
        activation_id: input.activation_id,
        admission_receipt: input.admission_receipt,
        activation_request_receipt: input.activation_request_receipt,
        assessment_receipt: input.assessment_receipt,
        stages: input.stages,
        metrics: input.metrics,
        attrition: input.attrition,
        confounders: input.confounders,
        independent_evaluator_receipt: input.independent_evaluator_receipt,
        dimensions: input.dimensions,
        external_review_refs: input.external_review_refs,
    };
    bounded_serialized_len(
        &bounded,
        input.policy.max_input_bytes.min(MAX_INPUT_BYTES),
        "input",
    )?;
    Ok(())
}
