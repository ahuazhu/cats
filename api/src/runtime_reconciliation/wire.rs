use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::LazyLock;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{de::DeserializeOwned, Serialize};

use super::canonical::{
    guest_config_digest, unchecked_inventory_digest, unchecked_key_ring_digest,
    unchecked_spec_digest, value_bytes,
};
use super::types::*;

pub const NODE_IDENTITY_MAX_WIRE_BYTES: usize = 16_384;
pub const AGENT_REGISTRATION_ATTEMPT_MAX_WIRE_BYTES: usize = 16_384;
pub const AGENT_SESSION_MAX_WIRE_BYTES: usize = 16_384;
pub const GUEST_RUNTIME_PROFILE_RECEIPT_MAX_WIRE_BYTES: usize = 4_096;
pub const ADMISSION_INVENTORY_ATTESTATION_MAX_WIRE_BYTES: usize = 16_384;
pub const DESIRED_READ_REQUEST_MAX_WIRE_BYTES: usize = 16_384;
pub const DESIRED_READ_SNAPSHOT_MAX_WIRE_BYTES: usize = 16_777_216;
pub const DESIRED_RUNTIME_SPEC_MAX_WIRE_BYTES: usize = 1_048_576;
pub const RUNTIME_CHECKPOINT_MAX_WIRE_BYTES: usize = 4_194_304;
pub const NODE_CLEANUP_CHECKPOINT_MAX_WIRE_BYTES: usize = 65_536;
pub const NODE_OBSERVATION_MAX_WIRE_BYTES: usize = 8_388_608;
pub const OBSERVATION_ACCEPTANCE_MAX_WIRE_BYTES: usize = 16_384;
pub const RUNTIME_SPINE_ERROR_MAX_WIRE_BYTES: usize = 20_480;
pub const RUNTIME_VOLUME_TRANSITION_REQUEST_MAX_WIRE_BYTES: usize = 16_384;
pub const RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES: usize = 16_384;
pub const RUNTIME_VOLUME_TRANSITION_EVIDENCE_REQUEST_MAX_WIRE_BYTES: usize = 4_096;
pub const RUNTIME_VOLUME_TRANSITION_EVIDENCE_SUCCESS_MAX_WIRE_BYTES: usize = 32_768;
pub const RUNTIME_VOLUME_TRANSITION_ERROR_MAX_WIRE_BYTES: usize = 20_480;
pub const OPERATION_MAX_WIRE_BYTES: usize = 65_536;
pub const CONTRACT_ERROR_MAX_WIRE_BYTES: usize = 16_384;
pub const PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES: usize = 4_096;
pub const PROVISION_ROOT_IMAGE_RESULT_MAX_WIRE_BYTES: usize = 4_096;
pub const PROVISION_ROOT_IMAGE_ERROR_MAX_WIRE_BYTES: usize = 4_096;
pub const NODE_PLACEMENT_POLICY_MAX_WIRE_BYTES: usize = 65_536;
pub const RUNTIME_NODE_AUTHORITY_APPLY_MAX_WIRE_BYTES: usize = 65_536;
pub const RUNTIME_NODE_AUTHORITY_APPLY_RESULT_MAX_WIRE_BYTES: usize = 16_384;
pub const RUNTIME_PROVISIONER_TRUST_BUNDLE_MAX_WIRE_BYTES: usize = 16_384;
pub const RUNTIME_PROVISIONER_ACTIVE_SET_MAX_WIRE_BYTES: usize = 16_384;

const MEBIBYTE: u64 = 1_048_576;

fn launch_file_parents_are_equal_or_disjoint(paths: &[&HostPath]) -> bool {
    for (index, left) in paths.iter().enumerate() {
        let Some(left_parent) = Path::new(left.as_str()).parent() else {
            return false;
        };
        for right in &paths[index + 1..] {
            let Some(right_parent) = Path::new(right.as_str()).parent() else {
                return false;
            };
            if left_parent != right_parent
                && (left_parent.starts_with(right_parent) || right_parent.starts_with(left_parent))
            {
                return false;
            }
        }
    }
    true
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PathSegment {
    Key(String),
    Index(usize),
}

impl Ord for PathSegment {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Key(left), Self::Key(right)) => left.as_bytes().cmp(right.as_bytes()),
            (Self::Index(left), Self::Index(right)) => left.cmp(right),
            // A JSON path cannot have a key and an index at the same parent in one schema.
            // Keep the order total for defensive use on malformed inputs.
            (Self::Key(_), Self::Index(_)) => Ordering::Less,
            (Self::Index(_), Self::Key(_)) => Ordering::Greater,
        }
    }
}

impl PartialOrd for PathSegment {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Candidate {
    path: Vec<PathSegment>,
    problem: MalformedProblem,
}

impl Candidate {
    fn field(path: &[PathSegment], field: &str, problem: MalformedProblem) -> Self {
        let mut path = path.to_vec();
        path.push(PathSegment::Key(field.to_owned()));
        Self { path, problem }
    }

    fn at(path: &[PathSegment], problem: MalformedProblem) -> Self {
        Self {
            path: path.to_vec(),
            problem,
        }
    }
}

fn compare_candidate_parts(
    path: &[PathSegment],
    field: Option<&str>,
    problem: MalformedProblem,
    current: &Candidate,
) -> Ordering {
    let candidate_length = path.len() + usize::from(field.is_some());
    for index in 0..candidate_length.min(current.path.len()) {
        let ordering = if let Some(segment) = path.get(index) {
            segment.cmp(&current.path[index])
        } else {
            let field = field.expect("the appended path segment exists");
            match &current.path[index] {
                PathSegment::Key(current) => field.as_bytes().cmp(current.as_bytes()),
                PathSegment::Index(_) => Ordering::Less,
            }
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    candidate_length
        .cmp(&current.path.len())
        .then_with(|| problem_rank(problem).cmp(&problem_rank(current.problem)))
}

fn consider_at(current: &mut Option<Candidate>, path: &[PathSegment], problem: MalformedProblem) {
    if current.as_ref().is_none_or(|candidate| {
        compare_candidate_parts(path, None, problem, candidate) == Ordering::Less
    }) {
        *current = Some(Candidate::at(path, problem));
    }
}

fn consider_field(
    current: &mut Option<Candidate>,
    path: &[PathSegment],
    field: &str,
    problem: MalformedProblem,
) {
    if current.as_ref().is_none_or(|candidate| {
        compare_candidate_parts(path, Some(field), problem, candidate) == Ordering::Less
    }) {
        *current = Some(Candidate::field(path, field, problem));
    }
}

fn consider_limit(current: &mut Option<(Candidate, usize)>, path: &[PathSegment], maximum: usize) {
    let problem = MalformedProblem::InvalidValue;
    if current.as_ref().is_none_or(|(candidate, _)| {
        compare_candidate_parts(path, None, problem, candidate) == Ordering::Less
    }) {
        *current = Some((Candidate::at(path, problem), maximum));
    }
}

fn subtree_can_improve(path: &[PathSegment], current: &Candidate) -> bool {
    for (left, right) in path.iter().zip(&current.path) {
        match left.cmp(right) {
            Ordering::Less => return true,
            Ordering::Greater => return false,
            Ordering::Equal => {}
        }
    }
    path.len() <= current.path.len()
}

// serde_json deliberately normalizes duplicate members and integer lexemes.
// This private, flat token stream preserves both until the deterministic
// validation stages finish. One eight-byte token represents each JSON value
// (plus each object key), so storage stays linear in the bounded wire input;
// nesting does not allocate one Vec per container.
const TOKEN_TAG_SHIFT: u32 = 56;
const TOKEN_PART_BITS: u32 = 28;
const TOKEN_PART_MASK: u64 = (1_u64 << TOKEN_PART_BITS) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum TokenTag {
    Null = 0,
    False = 1,
    True = 2,
    Number = 3,
    String = 4,
    Array = 5,
    Object = 6,
    Key = 7,
}

#[derive(Debug, Clone, Copy)]
struct RawToken(u64);

impl RawToken {
    fn scalar(tag: TokenTag) -> Self {
        Self((tag as u64) << TOKEN_TAG_SHIFT)
    }

    fn span(tag: TokenTag, start: usize, length: usize) -> Result<Self, usize> {
        let start = u64::try_from(start).map_err(|_| start)?;
        let length = u64::try_from(length).map_err(|_| length)?;
        if start > TOKEN_PART_MASK || length > TOKEN_PART_MASK {
            return Err(usize::try_from(start).unwrap_or(usize::MAX));
        }
        Ok(Self(
            ((tag as u64) << TOKEN_TAG_SHIFT) | (start << TOKEN_PART_BITS) | length,
        ))
    }

    fn container(tag: TokenTag) -> Self {
        Self::scalar(tag)
    }

    fn tag(self) -> TokenTag {
        match (self.0 >> TOKEN_TAG_SHIFT) as u8 {
            0 => TokenTag::Null,
            1 => TokenTag::False,
            2 => TokenTag::True,
            3 => TokenTag::Number,
            4 => TokenTag::String,
            5 => TokenTag::Array,
            6 => TokenTag::Object,
            7 => TokenTag::Key,
            _ => unreachable!("only private constructors create token tags"),
        }
    }

    fn span_start(self) -> usize {
        ((self.0 >> TOKEN_PART_BITS) & TOKEN_PART_MASK) as usize
    }

    fn span_length(self) -> usize {
        (self.0 & TOKEN_PART_MASK) as usize
    }

    fn set_container_end(&mut self, end: usize) -> Result<(), usize> {
        let end = u64::try_from(end).map_err(|_| end)?;
        if end > TOKEN_PART_MASK {
            return Err(usize::try_from(end).unwrap_or(usize::MAX));
        }
        self.0 = ((self.tag() as u64) << TOKEN_TAG_SHIFT) | end;
        Ok(())
    }

    fn container_end(self) -> usize {
        (self.0 & TOKEN_PART_MASK) as usize
    }
}

#[derive(Debug)]
struct RawDocument<'a> {
    input: &'a str,
    decoded_strings: String,
    tokens: Vec<RawToken>,
}

impl RawDocument<'_> {
    fn root(&self) -> usize {
        0
    }

    fn kind(&self, token: usize) -> PrimitiveKind {
        match self.tokens[token].tag() {
            TokenTag::Null => PrimitiveKind::Null,
            TokenTag::False | TokenTag::True => PrimitiveKind::Bool,
            TokenTag::Number => PrimitiveKind::Number,
            TokenTag::String => PrimitiveKind::String,
            TokenTag::Array => PrimitiveKind::Array,
            TokenTag::Object => PrimitiveKind::Object,
            TokenTag::Key => unreachable!("keys are not JSON values"),
        }
    }

    fn text(&self, token: usize) -> &str {
        let token = self.tokens[token];
        let start = token.span_start();
        let end = start + token.span_length();
        match token.tag() {
            TokenTag::Number => &self.input[start..end],
            TokenTag::String | TokenTag::Key => &self.decoded_strings[start..end],
            _ => unreachable!("only number and text tokens carry spans"),
        }
    }

    fn subtree_end(&self, token: usize) -> usize {
        match self.tokens[token].tag() {
            TokenTag::Array | TokenTag::Object => self.tokens[token].container_end(),
            _ => token + 1,
        }
    }

    fn array_items(&self, token: usize) -> ArrayItems<'_> {
        debug_assert_eq!(self.tokens[token].tag(), TokenTag::Array);
        ArrayItems {
            document: self,
            cursor: token + 1,
            end: self.subtree_end(token),
            index: 0,
        }
    }

    fn object_members(&self, token: usize) -> ObjectMembers<'_> {
        debug_assert_eq!(self.tokens[token].tag(), TokenTag::Object);
        ObjectMembers {
            document: self,
            cursor: token + 1,
            end: self.subtree_end(token),
        }
    }

    fn object_entries(&self, token: usize) -> ObjectEntries<'_> {
        debug_assert_eq!(self.tokens[token].tag(), TokenTag::Object);
        ObjectEntries {
            document: self,
            cursor: token + 1,
            end: self.subtree_end(token),
        }
    }

    fn object_member(&self, token: usize, name: &str) -> Option<usize> {
        self.object_members(token)
            .find_map(|(key, value)| (key == name).then_some(value))
    }
}

struct ArrayItems<'a> {
    document: &'a RawDocument<'a>,
    cursor: usize,
    end: usize,
    index: usize,
}

impl Iterator for ArrayItems<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.end {
            return None;
        }
        let token = self.cursor;
        self.cursor = self.document.subtree_end(token);
        let index = self.index;
        self.index += 1;
        Some((index, token))
    }
}

struct ObjectMembers<'a> {
    document: &'a RawDocument<'a>,
    cursor: usize,
    end: usize,
}

impl<'a> Iterator for ObjectMembers<'a> {
    type Item = (&'a str, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.end {
            return None;
        }
        let key = self.cursor;
        debug_assert_eq!(self.document.tokens[key].tag(), TokenTag::Key);
        let value = key + 1;
        self.cursor = self.document.subtree_end(value);
        Some((self.document.text(key), value))
    }
}

struct ObjectEntries<'a> {
    document: &'a RawDocument<'a>,
    cursor: usize,
    end: usize,
}

impl Iterator for ObjectEntries<'_> {
    type Item = (usize, usize);

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor >= self.end {
            return None;
        }
        let key = self.cursor;
        debug_assert_eq!(self.document.tokens[key].tag(), TokenTag::Key);
        let value = key + 1;
        self.cursor = self.document.subtree_end(value);
        Some((key, value))
    }
}

struct Parser<'a> {
    input: &'a str,
    bytes: &'a [u8],
    position: usize,
}

#[derive(Clone, Copy)]
struct ParseFrame {
    start: u32,
    kind: TokenTag,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input,
            bytes: input.as_bytes(),
            position: 0,
        }
    }

    fn parse(mut self) -> Result<RawDocument<'a>, usize> {
        let mut tokens = Vec::new();
        let mut decoded_strings = String::new();
        self.whitespace();
        let mut frames = Vec::new();
        let mut completed = self.begin_value(&mut frames, &mut tokens, &mut decoded_strings)?;
        loop {
            if completed {
                let Some(frame) = frames.last().copied() else {
                    self.whitespace();
                    if self.position != self.bytes.len() {
                        return Err(self.position);
                    }
                    return Ok(RawDocument {
                        input: self.input,
                        decoded_strings,
                        tokens,
                    });
                };
                self.whitespace();
                let (comma, closing) = match frame.kind {
                    TokenTag::Array => (b',', b']'),
                    TokenTag::Object => (b',', b'}'),
                    _ => unreachable!("parse frames only hold containers"),
                };
                if self.peek(closing) {
                    self.position += 1;
                    let frame = frames.pop().expect("a current frame exists");
                    let end = tokens.len();
                    tokens[frame.start as usize].set_container_end(end)?;
                    completed = true;
                } else if self.peek(comma) {
                    self.position += 1;
                    self.whitespace();
                    match frame.kind {
                        TokenTag::Array => {
                            completed =
                                self.begin_value(&mut frames, &mut tokens, &mut decoded_strings)?;
                        }
                        TokenTag::Object => {
                            if !self.peek(b'"') {
                                return Err(self.position);
                            }
                            let (start, length) = self.string(&mut decoded_strings)?;
                            tokens.push(RawToken::span(TokenTag::Key, start, length)?);
                            self.whitespace();
                            if !self.peek(b':') {
                                return Err(self.position);
                            }
                            self.position += 1;
                            self.whitespace();
                            completed =
                                self.begin_value(&mut frames, &mut tokens, &mut decoded_strings)?;
                        }
                        _ => unreachable!("parse frames only hold containers"),
                    }
                } else {
                    return Err(self.position);
                }
            } else {
                self.whitespace();
                let frame = frames.last().copied().ok_or(self.position)?;
                match frame.kind {
                    TokenTag::Array if self.peek(b']') => {
                        self.position += 1;
                        let frame = frames.pop().expect("a current frame exists");
                        let end = tokens.len();
                        tokens[frame.start as usize].set_container_end(end)?;
                        completed = true;
                    }
                    TokenTag::Array => {
                        completed =
                            self.begin_value(&mut frames, &mut tokens, &mut decoded_strings)?;
                    }
                    TokenTag::Object if self.peek(b'}') => {
                        self.position += 1;
                        let frame = frames.pop().expect("a current frame exists");
                        let end = tokens.len();
                        tokens[frame.start as usize].set_container_end(end)?;
                        completed = true;
                    }
                    TokenTag::Object => {
                        if !self.peek(b'"') {
                            return Err(self.position);
                        }
                        let (start, length) = self.string(&mut decoded_strings)?;
                        tokens.push(RawToken::span(TokenTag::Key, start, length)?);
                        self.whitespace();
                        if !self.peek(b':') {
                            return Err(self.position);
                        }
                        self.position += 1;
                        self.whitespace();
                        completed =
                            self.begin_value(&mut frames, &mut tokens, &mut decoded_strings)?;
                    }
                    _ => unreachable!("parse frames only hold containers"),
                }
            }
        }
    }

    fn begin_value(
        &mut self,
        frames: &mut Vec<ParseFrame>,
        tokens: &mut Vec<RawToken>,
        decoded_strings: &mut String,
    ) -> Result<bool, usize> {
        match self.bytes.get(self.position).copied() {
            Some(b'n') => {
                self.literal(b"null")?;
                tokens.push(RawToken::scalar(TokenTag::Null));
                Ok(true)
            }
            Some(b't') => {
                self.literal(b"true")?;
                tokens.push(RawToken::scalar(TokenTag::True));
                Ok(true)
            }
            Some(b'f') => {
                self.literal(b"false")?;
                tokens.push(RawToken::scalar(TokenTag::False));
                Ok(true)
            }
            Some(b'"') => {
                let (start, length) = self.string(decoded_strings)?;
                tokens.push(RawToken::span(TokenTag::String, start, length)?);
                Ok(true)
            }
            Some(b'[') => {
                self.position += 1;
                let start = tokens.len();
                tokens.push(RawToken::container(TokenTag::Array));
                frames.push(ParseFrame {
                    start: u32::try_from(start).map_err(|_| self.position)?,
                    kind: TokenTag::Array,
                });
                Ok(false)
            }
            Some(b'{') => {
                self.position += 1;
                let start = tokens.len();
                tokens.push(RawToken::container(TokenTag::Object));
                frames.push(ParseFrame {
                    start: u32::try_from(start).map_err(|_| self.position)?,
                    kind: TokenTag::Object,
                });
                Ok(false)
            }
            Some(b'-' | b'0'..=b'9') => {
                let (start, length) = self.number()?;
                tokens.push(RawToken::span(TokenTag::Number, start, length)?);
                Ok(true)
            }
            _ => Err(self.position),
        }
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), usize> {
        if self.bytes.get(self.position..self.position + literal.len()) == Some(literal) {
            self.position += literal.len();
            Ok(())
        } else {
            Err(self.position)
        }
    }

    fn string(&mut self, decoded_strings: &mut String) -> Result<(usize, usize), usize> {
        let start = self.position;
        let mut escaped = false;
        self.position += 1;
        while let Some(byte) = self.bytes.get(self.position).copied() {
            match byte {
                b'"' => {
                    self.position += 1;
                    let decoded_start = decoded_strings.len();
                    if escaped {
                        let decoded: String =
                            serde_json::from_str(&self.input[start..self.position])
                                .map_err(|error| start + error.column().saturating_sub(1))?;
                        decoded_strings.push_str(&decoded);
                        return Ok((decoded_start, decoded.len()));
                    }
                    let decoded = &self.input[start + 1..self.position - 1];
                    decoded_strings.push_str(decoded);
                    return Ok((decoded_start, decoded.len()));
                }
                b'\\' => {
                    escaped = true;
                    self.position += 1;
                    if self.position >= self.bytes.len() {
                        return Err(self.position);
                    }
                    self.position += 1;
                }
                0..=0x1f => return Err(self.position),
                _ => self.position += 1,
            }
        }
        Err(self.position)
    }

    fn number(&mut self) -> Result<(usize, usize), usize> {
        let start = self.position;
        if self.peek(b'-') {
            self.position += 1;
        }
        match self.bytes.get(self.position).copied() {
            Some(b'0') => self.position += 1,
            Some(b'1'..=b'9') => {
                self.position += 1;
                while matches!(self.bytes.get(self.position), Some(b'0'..=b'9')) {
                    self.position += 1;
                }
            }
            _ => return Err(self.position),
        }
        if self.peek(b'.') {
            self.position += 1;
            let digits = self.position;
            while matches!(self.bytes.get(self.position), Some(b'0'..=b'9')) {
                self.position += 1;
            }
            if digits == self.position {
                return Err(self.position);
            }
        }
        if matches!(self.bytes.get(self.position), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.bytes.get(self.position), Some(b'+' | b'-')) {
                self.position += 1;
            }
            let digits = self.position;
            while matches!(self.bytes.get(self.position), Some(b'0'..=b'9')) {
                self.position += 1;
            }
            if digits == self.position {
                return Err(self.position);
            }
        }
        Ok((start, self.position - start))
    }

    fn whitespace(&mut self) {
        while matches!(
            self.bytes.get(self.position),
            Some(b' ' | b'\n' | b'\r' | b'\t')
        ) {
            self.position += 1;
        }
    }

    fn peek(&self, expected: u8) -> bool {
        self.bytes.get(self.position).copied() == Some(expected)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrimitiveKind {
    Null,
    Bool,
    Number,
    String,
    Array,
    Object,
}

#[derive(Debug)]
struct Field {
    name: &'static str,
    schema: Schema,
}

#[derive(Debug)]
struct Variant {
    tag: &'static str,
    fields: Vec<Field>,
}

#[derive(Debug)]
enum Schema {
    Object(Vec<Field>),
    Union {
        discriminator: &'static str,
        variants: Vec<Variant>,
    },
    Array {
        item: Box<Schema>,
        maximum: usize,
    },
    String(StringRule),
    Number(NumberRule),
    Bool,
    Nullable(Box<Schema>),
}

impl Schema {
    fn kind(&self) -> Option<PrimitiveKind> {
        match self {
            Self::Object(_) | Self::Union { .. } => Some(PrimitiveKind::Object),
            Self::Array { .. } => Some(PrimitiveKind::Array),
            Self::String(_) => Some(PrimitiveKind::String),
            Self::Number(_) => Some(PrimitiveKind::Number),
            Self::Bool => Some(PrimitiveKind::Bool),
            Self::Nullable(_) => None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum StringRule {
    Id,
    GuestDeviceSerial,
    AsciiText,
    JsonPointer,
    RandomId,
    Digest,
    KeyId,
    HostPath,
    Hostname,
    NodeTransportTarget,
    Ipv4,
    Mac,
    Base64UrlNoPad,
    Message,
    Closed(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy)]
struct NumberRule {
    minimum: u64,
    maximum: u64,
}

fn field(name: &'static str, schema: Schema) -> Field {
    Field { name, schema }
}

fn object(fields: Vec<Field>) -> Schema {
    Schema::Object(fields)
}

fn variant(tag: &'static str, fields: Vec<Field>) -> Variant {
    Variant { tag, fields }
}

fn union(discriminator: &'static str, variants: Vec<Variant>) -> Schema {
    Schema::Union {
        discriminator,
        variants,
    }
}

fn array(item: Schema, maximum: usize) -> Schema {
    Schema::Array {
        item: Box::new(item),
        maximum,
    }
}

fn nullable(schema: Schema) -> Schema {
    Schema::Nullable(Box::new(schema))
}

fn string(rule: StringRule) -> Schema {
    Schema::String(rule)
}

fn number(minimum: u64, maximum: u64) -> Schema {
    Schema::Number(NumberRule { minimum, maximum })
}

fn literal_number(value: u64) -> Schema {
    number(value, value)
}

fn closed(values: &'static [&'static str]) -> Schema {
    string(StringRule::Closed(values))
}

fn id() -> Schema {
    string(StringRule::Id)
}

fn random_id() -> Schema {
    string(StringRule::RandomId)
}

fn digest() -> Schema {
    string(StringRule::Digest)
}

fn base64url_no_pad() -> Schema {
    string(StringRule::Base64UrlNoPad)
}

fn epoch() -> Schema {
    number(1, MAX_WIRE_INTEGER)
}

fn revision() -> Schema {
    number(1, MAX_WIRE_INTEGER)
}

fn sequence() -> Schema {
    number(1, MAX_WIRE_INTEGER)
}

fn wire_u64() -> Schema {
    number(0, MAX_WIRE_INTEGER)
}

fn version() -> Schema {
    number(0, MAX_WIRE_INTEGER)
}

fn projected_version() -> Schema {
    literal_number(1)
}

#[derive(Default)]
struct SchemaCandidates {
    shape: Option<Candidate>,
    discriminator: Option<Candidate>,
    variant: Option<Candidate>,
}

const RAW_KEY_SEGMENT: u32 = 1 << 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RawPathSegment(u32);

impl RawPathSegment {
    fn key(token: usize) -> Self {
        let token = u32::try_from(token).expect("bounded wire token index fits u32");
        debug_assert_eq!(token & RAW_KEY_SEGMENT, 0);
        Self(RAW_KEY_SEGMENT | token)
    }

    fn index(index: usize) -> Self {
        let index = u32::try_from(index).expect("bounded wire array index fits u32");
        debug_assert_eq!(index & RAW_KEY_SEGMENT, 0);
        Self(index)
    }

    fn is_key(self) -> bool {
        self.0 & RAW_KEY_SEGMENT != 0
    }

    fn value(self) -> usize {
        (self.0 & !RAW_KEY_SEGMENT) as usize
    }
}

#[derive(Debug)]
struct RawCandidate {
    path: Vec<RawPathSegment>,
}

fn collect_duplicates(document: &RawDocument<'_>, root: usize) -> Option<RawCandidate> {
    const OBJECT_FRAME: u32 = 1 << 31;
    const ENTERED_FRAME: u32 = 1 << 30;
    const FRAME_VALUE_MASK: u32 = ENTERED_FRAME - 1;
    const DUPLICATE_VALUE: u32 = u32::MAX;

    #[derive(Clone, Copy)]
    struct ObjectEntry {
        key: u32,
        value: u32,
    }

    #[derive(Clone, Copy)]
    struct LogicalChild {
        segment: RawPathSegment,
        value: u32,
    }

    #[derive(Clone, Copy)]
    struct Frame {
        cursor: u32,
        end: u32,
        state: u32,
    }

    fn append_object_children(
        document: &RawDocument<'_>,
        object: usize,
        children: &mut Vec<LogicalChild>,
    ) -> Result<(u32, u32), usize> {
        fn compact(key: usize, value: usize) -> Result<ObjectEntry, usize> {
            Ok(ObjectEntry {
                key: u32::try_from(key).map_err(|_| key)?,
                value: u32::try_from(value).map_err(|_| value)?,
            })
        }

        let start = u32::try_from(children.len()).map_err(|_| object)?;
        let mut raw_entries = document.object_entries(object);
        let Some((first_key, first_value)) = raw_entries.next() else {
            return Ok((start, start));
        };
        let first = compact(first_key, first_value)?;
        let Some((second_key, second_value)) = raw_entries.next() else {
            children.push(LogicalChild {
                segment: RawPathSegment::key(first.key as usize),
                value: first.value,
            });
            let end = u32::try_from(children.len()).map_err(|_| object)?;
            return Ok((start, end));
        };
        let second = compact(second_key, second_value)?;
        let Some((third_key, third_value)) = raw_entries.next() else {
            let ordering = document
                .text(first.key as usize)
                .as_bytes()
                .cmp(document.text(second.key as usize).as_bytes());
            if ordering == Ordering::Equal {
                children.push(LogicalChild {
                    segment: RawPathSegment::key(first.key as usize),
                    value: DUPLICATE_VALUE,
                });
            } else {
                let (lower, upper) = if ordering == Ordering::Less {
                    (first, second)
                } else {
                    (second, first)
                };
                for entry in [lower, upper] {
                    children.push(LogicalChild {
                        segment: RawPathSegment::key(entry.key as usize),
                        value: entry.value,
                    });
                }
            }
            let end = u32::try_from(children.len()).map_err(|_| object)?;
            return Ok((start, end));
        };

        let mut entries = vec![first, second, compact(third_key, third_value)?];
        for (key, value) in raw_entries {
            entries.push(compact(key, value)?);
        }
        entries.sort_unstable_by(|left, right| {
            document
                .text(left.key as usize)
                .as_bytes()
                .cmp(document.text(right.key as usize).as_bytes())
                .then_with(|| left.key.cmp(&right.key))
        });

        let mut index = 0;
        while index < entries.len() {
            let key = document.text(entries[index].key as usize);
            let mut group_end = index + 1;
            while group_end < entries.len() && document.text(entries[group_end].key as usize) == key
            {
                group_end += 1;
            }
            let duplicate = group_end - index > 1;
            children.push(LogicalChild {
                segment: RawPathSegment::key(entries[index].key as usize),
                value: if duplicate {
                    DUPLICATE_VALUE
                } else {
                    entries[index].value
                },
            });
            if duplicate {
                // This key's duplicate path is a prefix of every same-key
                // descendant and precedes every larger key, so later members
                // cannot affect the global minimum.
                break;
            }
            index = group_end;
        }
        let end = u32::try_from(children.len()).map_err(|_| object)?;
        Ok((start, end))
    }

    impl Frame {
        fn new(
            document: &RawDocument<'_>,
            value: usize,
            entered: bool,
            object_children: &mut Vec<LogicalChild>,
        ) -> Result<Self, usize> {
            let (cursor, end, mut state) = if document.kind(value) == PrimitiveKind::Object {
                let (start, end) = append_object_children(document, value, object_children)?;
                (start, end, OBJECT_FRAME)
            } else {
                (
                    u32::try_from(value + 1).map_err(|_| value)?,
                    u32::try_from(document.subtree_end(value)).map_err(|_| value)?,
                    0,
                )
            };
            if entered {
                state |= ENTERED_FRAME;
            }
            Ok(Self { cursor, end, state })
        }

        fn is_object(self) -> bool {
            self.state & OBJECT_FRAME != 0
        }

        fn entered(self) -> bool {
            self.state & ENTERED_FRAME != 0
        }

        fn next_index(&mut self) -> usize {
            debug_assert!(!self.is_object());
            let index = self.state & FRAME_VALUE_MASK;
            self.state = (self.state & !FRAME_VALUE_MASK) | (index + 1);
            index as usize
        }
    }

    if !matches!(
        document.kind(root),
        PrimitiveKind::Array | PrimitiveKind::Object
    ) {
        return None;
    }
    let mut path = Vec::new();
    let mut object_children = Vec::new();
    let mut frames = vec![Frame::new(document, root, false, &mut object_children)
        .expect("bounded wire token positions fit the compact traversal frame")];

    while let Some(frame) = frames.last_mut() {
        if frame.cursor >= frame.end {
            let entered = frame.entered();
            frames.pop();
            if entered {
                path.pop();
            }
            continue;
        }

        let (value, segment) = if frame.is_object() {
            let child = object_children[frame.cursor as usize];
            frame.cursor += 1;
            if child.value == DUPLICATE_VALUE {
                let mut candidate = Vec::with_capacity(path.len() + 1);
                candidate.extend_from_slice(&path);
                candidate.push(child.segment);
                return Some(RawCandidate { path: candidate });
            }
            (child.value as usize, child.segment)
        } else {
            let value = frame.cursor as usize;
            let segment = RawPathSegment::index(frame.next_index());
            frame.cursor = u32::try_from(document.subtree_end(value))
                .expect("bounded wire token positions fit the compact traversal frame");
            (value, segment)
        };

        if matches!(
            document.kind(value),
            PrimitiveKind::Array | PrimitiveKind::Object
        ) {
            path.push(segment);
            frames.push(
                Frame::new(document, value, true, &mut object_children)
                    .expect("bounded wire token positions fit the compact traversal frame"),
            );
        }
    }
    None
}

fn collect_schema(
    schema: &Schema,
    document: &RawDocument<'_>,
    value: usize,
    path: &mut Vec<PathSegment>,
    output: &mut SchemaCandidates,
) {
    // Shape is the earliest schema substage. Once its current minimum precedes
    // this whole subtree, neither another shape problem nor a later union
    // substage below that subtree can affect the selected wire error.
    if output
        .shape
        .as_ref()
        .is_some_and(|current| !subtree_can_improve(path, current))
    {
        return;
    }
    match schema {
        Schema::Nullable(inner) => {
            if document.kind(value) != PrimitiveKind::Null {
                collect_schema(inner, document, value, path, output);
            }
        }
        Schema::Object(fields) => {
            if document.kind(value) != PrimitiveKind::Object {
                consider_at(&mut output.shape, path, MalformedProblem::InvalidType);
                return;
            }
            collect_object_shape(document, fields, value, path, &mut output.shape);
            for field in fields {
                if let Some(member) = document.object_member(value, field.name) {
                    if kind_matches(&field.schema, document.kind(member)) {
                        path.push(PathSegment::Key(field.name.to_owned()));
                        collect_schema(&field.schema, document, member, path, output);
                        path.pop();
                    }
                }
            }
        }
        Schema::Union {
            discriminator,
            variants,
        } => {
            if document.kind(value) != PrimitiveKind::Object {
                consider_at(&mut output.shape, path, MalformedProblem::InvalidType);
                return;
            }
            for (key, _) in document.object_members(value) {
                let allowed = key == *discriminator
                    || variants
                        .iter()
                        .any(|variant| variant.fields.iter().any(|field| field.name == key));
                if !allowed {
                    consider_field(&mut output.shape, path, key, MalformedProblem::UnknownField);
                }
            }
            let Some(tag_value) = document.object_member(value, discriminator) else {
                consider_field(
                    &mut output.shape,
                    path,
                    discriminator,
                    MalformedProblem::MissingField,
                );
                return;
            };
            if document.kind(tag_value) != PrimitiveKind::String {
                consider_field(
                    &mut output.shape,
                    path,
                    discriminator,
                    MalformedProblem::InvalidType,
                );
                return;
            }
            let tag = document.text(tag_value);
            let Some(selected) = variants.iter().find(|candidate| candidate.tag == tag) else {
                consider_field(
                    &mut output.discriminator,
                    path,
                    discriminator,
                    MalformedProblem::InvalidValue,
                );
                return;
            };
            collect_variant_shape(
                document,
                discriminator,
                &selected.fields,
                value,
                path,
                &mut output.variant,
            );
            for field in &selected.fields {
                if let Some(member) = document.object_member(value, field.name) {
                    if kind_matches(&field.schema, document.kind(member)) {
                        path.push(PathSegment::Key(field.name.to_owned()));
                        collect_schema(&field.schema, document, member, path, output);
                        path.pop();
                    }
                }
            }
        }
        Schema::Array { item, .. } => {
            if document.kind(value) != PrimitiveKind::Array {
                consider_at(&mut output.shape, path, MalformedProblem::InvalidType);
                return;
            }
            for (index, item_value) in document.array_items(value) {
                path.push(PathSegment::Index(index));
                collect_schema(item, document, item_value, path, output);
                path.pop();
            }
        }
        Schema::String(_) | Schema::Number(_) | Schema::Bool => {
            if !kind_matches(schema, document.kind(value)) {
                consider_at(&mut output.shape, path, MalformedProblem::InvalidType);
            }
        }
    }
}

fn collect_object_shape(
    document: &RawDocument<'_>,
    fields: &[Field],
    value: usize,
    path: &[PathSegment],
    output: &mut Option<Candidate>,
) {
    for (key, _) in document.object_members(value) {
        if !fields.iter().any(|field| field.name == key) {
            consider_field(output, path, key, MalformedProblem::UnknownField);
        }
    }
    for field in fields {
        match document.object_member(value, field.name) {
            None => consider_field(output, path, field.name, MalformedProblem::MissingField),
            Some(value) if !kind_matches(&field.schema, document.kind(value)) => {
                consider_field(output, path, field.name, MalformedProblem::InvalidType)
            }
            Some(_) => {}
        }
    }
}

fn collect_variant_shape(
    document: &RawDocument<'_>,
    discriminator: &str,
    fields: &[Field],
    value: usize,
    path: &[PathSegment],
    output: &mut Option<Candidate>,
) {
    for (key, _) in document.object_members(value) {
        if key != discriminator && !fields.iter().any(|field| field.name == key) {
            consider_field(output, path, key, MalformedProblem::UnknownField);
        }
    }
    for field in fields {
        match document.object_member(value, field.name) {
            None => consider_field(output, path, field.name, MalformedProblem::MissingField),
            Some(value) if !kind_matches(&field.schema, document.kind(value)) => {
                consider_field(output, path, field.name, MalformedProblem::InvalidType)
            }
            Some(_) => {}
        }
    }
}

fn kind_matches(schema: &Schema, value: PrimitiveKind) -> bool {
    match schema {
        Schema::Nullable(inner) => value == PrimitiveKind::Null || kind_matches(inner, value),
        _ => schema.kind() == Some(value),
    }
}

fn collect_limits(
    schema: &Schema,
    document: &RawDocument<'_>,
    value: usize,
    path: &mut Vec<PathSegment>,
    output: &mut Option<(Candidate, usize)>,
) {
    match schema {
        Schema::Nullable(_) if document.kind(value) == PrimitiveKind::Null => {}
        Schema::Nullable(inner) => collect_limits(inner, document, value, path, output),
        Schema::Object(fields) if document.kind(value) == PrimitiveKind::Object => {
            for field in fields {
                if let Some(value) = document.object_member(value, field.name) {
                    path.push(PathSegment::Key(field.name.to_owned()));
                    collect_limits(&field.schema, document, value, path, output);
                    path.pop();
                }
            }
        }
        Schema::Union {
            discriminator,
            variants,
        } if document.kind(value) == PrimitiveKind::Object => {
            if let Some(tag_value) = document.object_member(value, discriminator) {
                if document.kind(tag_value) != PrimitiveKind::String {
                    return;
                }
                let tag = document.text(tag_value);
                if let Some(selected) = variants.iter().find(|candidate| candidate.tag == tag) {
                    for field in &selected.fields {
                        if let Some(value) = document.object_member(value, field.name) {
                            path.push(PathSegment::Key(field.name.to_owned()));
                            collect_limits(&field.schema, document, value, path, output);
                            path.pop();
                        }
                    }
                }
            }
        }
        Schema::Array { item, maximum } if document.kind(value) == PrimitiveKind::Array => {
            let mut observed = 0;
            for (index, item_value) in document.array_items(value) {
                observed += 1;
                path.push(PathSegment::Index(index));
                collect_limits(item, document, item_value, path, output);
                path.pop();
            }
            if observed > *maximum {
                consider_limit(output, path, *maximum);
            }
        }
        _ => {}
    }
}

fn collect_scalars(
    schema: &Schema,
    document: &RawDocument<'_>,
    value: usize,
    path: &mut Vec<PathSegment>,
    output: &mut Option<Candidate>,
) {
    match schema {
        Schema::Nullable(_) if document.kind(value) == PrimitiveKind::Null => {}
        Schema::Nullable(inner) => collect_scalars(inner, document, value, path, output),
        Schema::Object(fields) if document.kind(value) == PrimitiveKind::Object => {
            for field in fields {
                if let Some(value) = document.object_member(value, field.name) {
                    path.push(PathSegment::Key(field.name.to_owned()));
                    collect_scalars(&field.schema, document, value, path, output);
                    path.pop();
                }
            }
        }
        Schema::Union {
            discriminator,
            variants,
        } if document.kind(value) == PrimitiveKind::Object => {
            if let Some(tag_value) = document.object_member(value, discriminator) {
                if document.kind(tag_value) != PrimitiveKind::String {
                    return;
                }
                let tag = document.text(tag_value);
                if let Some(selected) = variants.iter().find(|candidate| candidate.tag == tag) {
                    for field in &selected.fields {
                        if let Some(value) = document.object_member(value, field.name) {
                            path.push(PathSegment::Key(field.name.to_owned()));
                            collect_scalars(&field.schema, document, value, path, output);
                            path.pop();
                        }
                    }
                }
            }
        }
        Schema::Array { item, .. } if document.kind(value) == PrimitiveKind::Array => {
            for (index, value) in document.array_items(value) {
                path.push(PathSegment::Index(index));
                collect_scalars(item, document, value, path, output);
                path.pop();
            }
        }
        Schema::String(rule) if document.kind(value) == PrimitiveKind::String => {
            if !valid_string(*rule, document.text(value)) {
                consider_at(output, path, MalformedProblem::InvalidValue);
            }
        }
        Schema::Number(rule)
            if document.kind(value) == PrimitiveKind::Number
                && parse_wire_integer(document.text(value))
                    .is_none_or(|integer| integer < rule.minimum || integer > rule.maximum) =>
        {
            consider_at(output, path, MalformedProblem::InvalidValue);
        }
        _ => {}
    }
}

fn valid_string(rule: StringRule, value: &str) -> bool {
    match rule {
        StringRule::Id => valid_id(value),
        StringRule::GuestDeviceSerial => valid_guest_device_serial(value),
        StringRule::AsciiText => valid_ascii_text(value),
        StringRule::JsonPointer => valid_json_pointer(value),
        StringRule::RandomId => valid_random_id(value),
        StringRule::Digest => valid_digest(value),
        StringRule::KeyId => valid_key_id(value),
        StringRule::HostPath => valid_host_path(value),
        StringRule::Hostname => valid_hostname(value),
        StringRule::NodeTransportTarget => valid_node_transport_target(value),
        StringRule::Ipv4 => valid_ipv4(value),
        StringRule::Mac => valid_mac(value),
        StringRule::Base64UrlNoPad => valid_base64url_no_pad(value),
        StringRule::Message => {
            value.len() <= 1024 && !value.chars().any(|character| character.is_control())
        }
        StringRule::Closed(values) => values.contains(&value),
    }
}

fn parse_wire_integer(value: &str) -> Option<u64> {
    if value == "0" {
        return Some(0);
    }
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let mut result = 0_u64;
    for digit in value.bytes().map(|byte| u64::from(byte - b'0')) {
        result = result.checked_mul(10)?.checked_add(digit)?;
        if result > MAX_WIRE_INTEGER {
            return None;
        }
    }
    Some(result)
}

fn problem_rank(problem: MalformedProblem) -> u8 {
    match problem {
        MalformedProblem::MissingField => 0,
        MalformedProblem::UnknownField => 1,
        MalformedProblem::DuplicateField => 2,
        MalformedProblem::InvalidType => 3,
        MalformedProblem::InvalidValue => 4,
        MalformedProblem::DuplicateIdentity => 5,
        MalformedProblem::NonCanonicalOrder => 6,
        MalformedProblem::InvalidUtf8 | MalformedProblem::InvalidJson => 7,
    }
}

fn choose(candidates: impl IntoIterator<Item = Candidate>) -> Option<Candidate> {
    candidates.into_iter().min_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| problem_rank(left.problem).cmp(&problem_rank(right.problem)))
    })
}

fn render_pointer(path: &[PathSegment]) -> JsonPointer {
    let mut pointer = String::new();
    for segment in path {
        pointer.push('/');
        match segment {
            PathSegment::Index(index) => pointer.push_str(&index.to_string()),
            PathSegment::Key(key) => {
                for character in key.chars() {
                    match character {
                        '~' => pointer.push_str("~0"),
                        '/' => pointer.push_str("~1"),
                        _ => pointer.push(character),
                    }
                }
            }
        }
    }
    JsonPointer::new(pointer)
        .unwrap_or_else(|| JsonPointer::new("").expect("root pointer is valid"))
}

fn render_raw_pointer(document: &RawDocument<'_>, path: &[RawPathSegment]) -> JsonPointer {
    let mut pointer = String::new();
    for segment in path {
        pointer.push('/');
        if segment.is_key() {
            for character in document.text(segment.value()).chars() {
                match character {
                    '~' => pointer.push_str("~0"),
                    '/' => pointer.push_str("~1"),
                    _ => pointer.push(character),
                }
                if pointer.len() > 512 {
                    return JsonPointer::new("").expect("root pointer is valid");
                }
            }
        } else {
            pointer.push_str(&segment.value().to_string());
        }
        if pointer.len() > 512 {
            return JsonPointer::new("").expect("root pointer is valid");
        }
    }
    JsonPointer::new(pointer)
        .unwrap_or_else(|| JsonPointer::new("").expect("root pointer is valid"))
}

enum PayloadValidationError {
    Malformed {
        json_pointer: JsonPointer,
        problem: MalformedProblem,
    },
    LimitExceeded {
        json_pointer: JsonPointer,
        limit: LimitKind,
        maximum: usize,
    },
    UnsupportedVersion(u64),
}

fn payload_malformed(candidate: Candidate) -> PayloadValidationError {
    PayloadValidationError::Malformed {
        json_pointer: render_pointer(&candidate.path),
        problem: candidate.problem,
    }
}

fn payload_malformed_duplicate(
    document: &RawDocument<'_>,
    candidate: RawCandidate,
) -> PayloadValidationError {
    PayloadValidationError::Malformed {
        json_pointer: render_raw_pointer(document, &candidate.path),
        problem: MalformedProblem::DuplicateField,
    }
}

fn payload_malformed_root(problem: MalformedProblem) -> PayloadValidationError {
    payload_malformed(Candidate::at(&[], problem))
}

fn payload_limit(path: &[PathSegment], limit: LimitKind, maximum: usize) -> PayloadValidationError {
    PayloadValidationError::LimitExceeded {
        json_pointer: render_pointer(path),
        limit,
        maximum,
    }
}

fn malformed(contract: ContractName, candidate: Candidate) -> ContractError {
    ContractError {
        version: ContractVersion::V1,
        error: Box::new(ContractErrorDetail::MalformedPayload {
            contract,
            json_pointer: render_pointer(&candidate.path),
            problem: candidate.problem,
        }),
        message: "runtime reconciliation contract validation failed".to_owned(),
    }
}

fn malformed_root(contract: ContractName, problem: MalformedProblem) -> ContractError {
    malformed(contract, Candidate::at(&[], problem))
}

fn limit_error(
    contract: ContractName,
    path: &[PathSegment],
    limit: LimitKind,
    maximum: usize,
) -> ContractError {
    ContractError {
        version: ContractVersion::V1,
        error: Box::new(ContractErrorDetail::LimitExceeded {
            contract,
            json_pointer: render_pointer(path),
            limit,
            maximum: WireU64::new(maximum as u64).expect("contract limits fit the wire range"),
            observed_at_least: WireU64::new(maximum as u64 + 1)
                .expect("contract limits plus one fit the wire range"),
        }),
        message: "runtime reconciliation contract limit exceeded".to_owned(),
    }
}

fn unsupported_version(contract: ContractName, presented: u64) -> ContractError {
    ContractError {
        version: ContractVersion::V1,
        error: Box::new(ContractErrorDetail::UnsupportedVersion {
            contract,
            supported_version: ContractVersion::V1,
            presented_version: ContractVersion::new(presented)
                .expect("presented version was checked against the wire range"),
        }),
        message: "runtime reconciliation contract version is unsupported".to_owned(),
    }
}

fn contract_payload_error(contract: ContractName, error: PayloadValidationError) -> ContractError {
    match error {
        PayloadValidationError::Malformed {
            json_pointer,
            problem,
        } => ContractError {
            version: ContractVersion::V1,
            error: Box::new(ContractErrorDetail::MalformedPayload {
                contract,
                json_pointer,
                problem,
            }),
            message: "runtime reconciliation contract validation failed".to_owned(),
        },
        PayloadValidationError::LimitExceeded {
            json_pointer,
            limit,
            maximum,
        } => ContractError {
            version: ContractVersion::V1,
            error: Box::new(ContractErrorDetail::LimitExceeded {
                contract,
                json_pointer,
                limit,
                maximum: WireU64::new(maximum as u64).expect("contract limits fit the wire range"),
                observed_at_least: WireU64::new(maximum as u64 + 1)
                    .expect("contract limits plus one fit the wire range"),
            }),
            message: "runtime reconciliation contract limit exceeded".to_owned(),
        },
        PayloadValidationError::UnsupportedVersion(presented) => {
            unsupported_version(contract, presented)
        }
    }
}

fn validate_payload<'a>(
    bytes: &'a [u8],
    maximum_bytes: usize,
    schema: &Schema,
    validate_v1_version: bool,
) -> Result<&'a str, PayloadValidationError> {
    if bytes.len() > maximum_bytes {
        return Err(payload_limit(&[], LimitKind::WireBytes, maximum_bytes));
    }
    let input = std::str::from_utf8(bytes)
        .map_err(|_| payload_malformed_root(MalformedProblem::InvalidUtf8))?;
    let raw = Parser::new(input)
        .parse()
        .map_err(|_| payload_malformed_root(MalformedProblem::InvalidJson))?;
    let root = raw.root();

    if let Some(candidate) = collect_duplicates(&raw, root) {
        return Err(payload_malformed_duplicate(&raw, candidate));
    }

    let mut schema_candidates = SchemaCandidates::default();
    collect_schema(schema, &raw, root, &mut Vec::new(), &mut schema_candidates);
    if let Some(candidate) = schema_candidates
        .shape
        .or(schema_candidates.discriminator)
        .or(schema_candidates.variant)
    {
        return Err(payload_malformed(candidate));
    }

    if validate_v1_version {
        let version_value = raw
            .object_member(root, "version")
            .and_then(|value| {
                (raw.kind(value) == PrimitiveKind::Number)
                    .then(|| parse_wire_integer(raw.text(value)))
                    .flatten()
            })
            .ok_or_else(|| {
                payload_malformed(Candidate::field(
                    &[],
                    "version",
                    MalformedProblem::InvalidValue,
                ))
            })?;
        if version_value != 1 {
            return Err(PayloadValidationError::UnsupportedVersion(version_value));
        }
    }

    let mut limit = None;
    collect_limits(schema, &raw, root, &mut Vec::new(), &mut limit);
    if let Some((candidate, maximum)) = limit {
        return Err(payload_limit(
            &candidate.path,
            LimitKind::ArrayItems,
            maximum,
        ));
    }

    let mut scalar = None;
    collect_scalars(schema, &raw, root, &mut Vec::new(), &mut scalar);
    if let Some(candidate) = scalar {
        return Err(payload_malformed(candidate));
    }

    Ok(input)
}

fn decode<T>(
    bytes: &[u8],
    contract: ContractName,
    maximum_bytes: usize,
    schema: &Schema,
    validate: impl FnOnce(&T) -> Result<(), ContractError>,
) -> Result<T, ContractError>
where
    T: DeserializeOwned,
{
    let input = validate_payload(bytes, maximum_bytes, schema, true)
        .map_err(|error| contract_payload_error(contract, error))?;

    let decoded = serde_json::from_str(input)
        .map_err(|_| malformed_root(contract, MalformedProblem::InvalidValue))?;
    validate(&decoded)?;
    Ok(decoded)
}

fn encode<T>(
    value: &T,
    contract: ContractName,
    decode: fn(&[u8]) -> Result<T, ContractError>,
) -> Result<Vec<u8>, ContractError>
where
    T: Serialize,
{
    let value = serde_json::to_value(value)
        .map_err(|_| malformed_root(contract, MalformedProblem::InvalidValue))?;
    let bytes = value_bytes(&value);
    decode(&bytes)?;
    Ok(bytes)
}

fn assigned_placement_schema() -> Schema {
    object(vec![
        field("kind", closed(&["assigned"])),
        field("node_id", id()),
        field("placement_epoch", epoch()),
    ])
}

fn credential_binding_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "public_key",
                vec![field("public_key_spki_sha256", digest())],
            ),
            variant(
                "provider_principal",
                vec![
                    field("provider", id()),
                    field("principal", string(StringRule::AsciiText)),
                ],
            ),
        ],
    )
}

fn runtime_target_schema() -> Schema {
    closed(&["running", "suspended", "warm", "cold", "deleted"])
}

fn stable_state_schema() -> Schema {
    runtime_target_schema()
}

fn guest_device_schema() -> Schema {
    object(vec![
        field("serial", string(StringRule::GuestDeviceSerial)),
        field("slot", number(0, u64::from(u16::MAX))),
    ])
}

fn network_config_schema() -> Schema {
    object(vec![
        field("kind", closed(&["isolated_ipv4"])),
        field("network_id", id()),
        field("guest_mac", string(StringRule::Mac)),
        field("guest_ipv4", string(StringRule::Ipv4)),
        field("prefix_length", literal_number(30)),
        field("gateway_ipv4", string(StringRule::Ipv4)),
    ])
}

fn volume_acquire_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "normal",
                vec![
                    field("transition_id", random_id()),
                    field("expected_unowned_epoch", wire_u64()),
                ],
            ),
            variant("takeover", vec![field("authorization_id", id())]),
        ],
    )
}

fn volume_acquire_request_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "normal",
                vec![
                    field("volume_id", id()),
                    field("transition_id", random_id()),
                    field("attachment_id", id()),
                    field("expected_unowned_epoch", wire_u64()),
                    field("desired_revision", revision()),
                    field("placement_epoch", epoch()),
                    field("lease_duration_ms", number(1, MAX_WIRE_INTEGER)),
                ],
            ),
            variant("takeover", vec![field("authorization_id", id())]),
        ],
    )
}

fn volume_disposition_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("retain", vec![]),
            variant("detach_retained", vec![]),
            variant("delete_disposable_root", vec![field("delete_id", id())]),
        ],
    )
}

fn filesystem_initialization_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("existing", vec![]),
            variant(
                "initialize",
                vec![
                    field("initialization_token", random_id()),
                    field("expected_blank_head", remote_head_schema()),
                ],
            ),
        ],
    )
}

fn mount_intent_schema() -> Schema {
    object(vec![
        field("filesystem_uuid", random_id()),
        field("mount_path", string(StringRule::HostPath)),
        field("initialization", filesystem_initialization_schema()),
    ])
}

fn persistent_filesystem_binding_schema() -> Schema {
    object(vec![
        field("runtime_incarnation", random_id()),
        field("volume_intent_id", id()),
        field("disk_id", id()),
        field("volume_id", id()),
        field("attachment_id", id()),
        field("attachment_epoch", number(1, MAX_WIRE_INTEGER)),
        field("size_bytes", number(1, MAX_WIRE_INTEGER)),
        field("guest_device", guest_device_schema()),
        field("filesystem_uuid", random_id()),
        field("mount_path", string(StringRule::HostPath)),
        field("initialization", filesystem_initialization_schema()),
    ])
}

fn volume_intent_schema() -> Schema {
    object(vec![
        field("volume_intent_id", id()),
        field("disk_id", id()),
        field("volume_id", id()),
        field("attachment_id", id()),
        field("size_bytes", number(1, MAX_WIRE_INTEGER)),
        field("disk_kind", closed(&["root", "persistent"])),
        field("access", closed(&["read_write_once"])),
        field("durability", closed(&["strict", "relaxed"])),
        field("guest_device", guest_device_schema()),
        field("acquire", volume_acquire_schema()),
        field("disposition", volume_disposition_schema()),
        field("mount", nullable(mount_intent_schema())),
    ])
}

fn endpoint_intent_schema() -> Schema {
    object(vec![
        field("endpoint_id", id()),
        field("hostname", string(StringRule::Hostname)),
        field("route_epoch", epoch()),
        field("protocol", closed(&["http"])),
        field("target_port", number(1, u64::from(u16::MAX))),
    ])
}

fn desired_runtime_spec_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("workspace_id", id()),
        field("cat_id", id()),
        field("desired_revision", revision()),
        field("target", runtime_target_schema()),
        field("placement", assigned_placement_schema()),
        field(
            "runtime",
            object(vec![
                field("vcpus", number(1, u64::from(u32::MAX))),
                field("memory_bytes", number(1, MAX_WIRE_INTEGER)),
                field("boot_image_digest", digest()),
                field("guest_config_digest", digest()),
                field("network_config", network_config_schema()),
            ]),
        ),
        field("volumes", array(volume_intent_schema(), 64)),
        field("endpoints", array(endpoint_intent_schema(), 256)),
        field(
            "transition",
            union(
                "kind",
                vec![
                    variant("cancel_and_drain", vec![]),
                    variant(
                        "require_idle",
                        vec![
                            field("attempt_id", random_id()),
                            field("source_revision", revision()),
                            field("source_runtime_incarnation", random_id()),
                        ],
                    ),
                ],
            ),
        ),
        field("spec_digest", digest()),
    ])
}

fn endpoint_guard_schema() -> Schema {
    object(vec![
        field("endpoint_id", id()),
        field("active_guards", number(1, u64::from(u32::MAX))),
    ])
}

fn require_idle_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("not_applicable", vec![]),
            variant(
                "armed",
                vec![
                    field("attempt_id", random_id()),
                    field("source_revision", revision()),
                    field("source_runtime_incarnation", random_id()),
                ],
            ),
            variant(
                "busy",
                vec![
                    field("attempt_id", random_id()),
                    field("source_revision", revision()),
                    field("source_runtime_incarnation", random_id()),
                    field("gate_closed", Schema::Bool),
                    field("platform_guards", number(0, u64::from(u32::MAX))),
                    field("endpoint_guards", array(endpoint_guard_schema(), 256)),
                ],
            ),
            variant(
                "closed",
                vec![
                    field("attempt_id", random_id()),
                    field("source_revision", revision()),
                    field("source_runtime_incarnation", random_id()),
                ],
            ),
        ],
    )
}

fn session_binding_schema() -> Schema {
    object(vec![
        field("node_id", id()),
        field("node_boot_id", random_id()),
        field("agent_instance_id", random_id()),
        field("agent_session_epoch", epoch()),
    ])
}

fn volume_release_replay_schema() -> Schema {
    object(vec![
        field("release_transition_id", random_id()),
        field("generation", wire_u64()),
        field("disposition", volume_disposition_schema()),
    ])
}

fn cleanup_target_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "volume",
                vec![
                    field("volume_id", id()),
                    field("attachment_id", id()),
                    field("attachment_epoch", wire_u64()),
                ],
            ),
            variant(
                "device",
                vec![
                    field("volume_id", id()),
                    field("ownership_token", random_id()),
                ],
            ),
            variant(
                "network",
                vec![
                    field("network_id", id()),
                    field("ownership_token", random_id()),
                ],
            ),
            variant("warm_snapshot", vec![field("snapshot_id", id())]),
            variant(
                "scope",
                vec![
                    field("scope_id", id()),
                    field("process_start_time_ticks", wire_u64()),
                ],
            ),
            variant(
                "orphan_scope",
                vec![
                    field("scope_id", id()),
                    field("cgroup_path", string(StringRule::HostPath)),
                    field("ownership_token", random_id()),
                ],
            ),
            variant(
                "control_socket",
                vec![
                    field("socket_path", string(StringRule::HostPath)),
                    field("ownership_token", random_id()),
                ],
            ),
            variant(
                "checkpoint_file",
                vec![
                    field("checkpoint_path", string(StringRule::HostPath)),
                    field("content_digest", digest()),
                    field("cat_id", id()),
                    field("node_id", id()),
                    field("placement_epoch", epoch()),
                    field("desired_revision", revision()),
                ],
            ),
        ],
    )
}

fn cleanup_release_schema() -> Schema {
    object(vec![
        field("target", cleanup_target_schema()),
        field("inventory_session", session_binding_schema()),
        field("inventory_epoch", epoch()),
        field("inventory_read_position", sequence()),
        field("desired_read_position", sequence()),
        field("volume_release", nullable(volume_release_replay_schema())),
    ])
}

fn volume_head_schema() -> Schema {
    object(vec![
        field("volume_id", id()),
        field("attachment_epoch", wire_u64()),
        field("head", remote_head_schema()),
    ])
}

fn remote_head_schema() -> Schema {
    object(vec![
        field("generation", wire_u64()),
        field("root_hash", nullable(digest())),
        field("root_object_id", nullable(string(StringRule::AsciiText))),
    ])
}

fn normal_acquire_request_schema() -> Schema {
    object(vec![
        field("volume_id", id()),
        field("transition_id", random_id()),
        field("attachment_id", id()),
        field("expected_unowned_epoch", wire_u64()),
        field("desired_revision", revision()),
        field("placement_epoch", epoch()),
        field("lease_duration_ms", number(1, MAX_WIRE_INTEGER)),
    ])
}

fn normal_acquire_result_schema() -> Schema {
    object(vec![
        field("volume_id", id()),
        field("transition_id", random_id()),
        field("attachment_id", id()),
        field("resulting_epoch", wire_u64()),
        field("resulting_head", remote_head_schema()),
        field("lease_expires_at", wire_u64()),
    ])
}

fn release_request_schema() -> Schema {
    object(vec![
        field("volume_id", id()),
        field("transition_id", random_id()),
        field("attachment_id", id()),
        field("expected_epoch", wire_u64()),
    ])
}

fn release_result_schema() -> Schema {
    object(vec![
        field("volume_id", id()),
        field("transition_id", random_id()),
        field("released_attachment_id", id()),
        field("resulting_epoch", wire_u64()),
        field("resulting_head", remote_head_schema()),
    ])
}

fn begin_delete_request_schema() -> Schema {
    object(vec![
        field("delete_id", id()),
        field("disk_id", id()),
        field("volume_id", id()),
        field("expected_unowned_epoch", wire_u64()),
        field("expected_head", remote_head_schema()),
    ])
}

fn begin_delete_result_schema() -> Schema {
    object(vec![
        field("delete_id", id()),
        field("disk_id", id()),
        field("volume_id", id()),
        field("resulting_epoch", wire_u64()),
        field("resulting_head", remote_head_schema()),
    ])
}

fn volume_admin_state_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("active", vec![]),
            variant("deleting", vec![field("delete_id", id())]),
        ],
    )
}

fn last_volume_transition_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "normal_acquire",
                vec![
                    field("request", normal_acquire_request_schema()),
                    field("result", normal_acquire_result_schema()),
                ],
            ),
            variant(
                "release",
                vec![
                    field("request", release_request_schema()),
                    field("result", release_result_schema()),
                ],
            ),
            variant("takeover", vec![field("authorization_id", id())]),
            variant(
                "begin_delete",
                vec![
                    field("request", begin_delete_request_schema()),
                    field("result", begin_delete_result_schema()),
                ],
            ),
            variant(
                "begin_disposable_delete",
                vec![field("authorization_id", id())],
            ),
        ],
    )
}

fn volume_record_schema() -> Schema {
    object(vec![
        field("volume_id", id()),
        field("size_bytes", number(1, MAX_WIRE_INTEGER)),
        field("durability", closed(&["strict", "relaxed"])),
        field("admin_state", volume_admin_state_schema()),
        field("head", remote_head_schema()),
        field("lease_owner", nullable(id())),
        field("lease_epoch", wire_u64()),
        field("lease_expires_at", nullable(wire_u64())),
        field("last_transition", nullable(last_volume_transition_schema())),
    ])
}

fn takeover_authorization_fields() -> Vec<Field> {
    vec![
        field("authorization_id", id()),
        field("authorized_node_id", id()),
        field("host_fence_event_id", id()),
        field("volume_id", id()),
        field("expected_attachment_id", id()),
        field("expected_epoch", wire_u64()),
        field("new_attachment_id", id()),
        field("desired_revision", revision()),
        field("new_placement_epoch", epoch()),
        field("lease_duration_ms", number(1, MAX_WIRE_INTEGER)),
        field("not_after", wire_u64()),
    ]
}

fn disposable_delete_isolation_basis_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "runtime_stopped",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("runtime_incarnation", random_id()),
                    field("observation_id", random_id()),
                ],
            ),
            variant("host_fence_event", vec![field("event_id", id())]),
        ],
    )
}

fn disposable_delete_authorization_fields() -> Vec<Field> {
    vec![
        field("authorization_id", id()),
        field("authorized_node_id", id()),
        field("delete_id", id()),
        field("disk_id", id()),
        field("volume_id", id()),
        field("cat_id", id()),
        field("desired_revision", revision()),
        field("placement_epoch", epoch()),
        field("expected_attachment_id", id()),
        field("expected_epoch", wire_u64()),
        field("expected_head", remote_head_schema()),
        field(
            "isolation_basis",
            disposable_delete_isolation_basis_schema(),
        ),
        field("not_after", wire_u64()),
    ]
}

fn takeover_consumed_receipt_fields() -> Vec<Field> {
    vec![
        field("authorization_id", id()),
        field("host_fence_event_id", id()),
        field("volume_id", id()),
        field("new_attachment_id", id()),
        field("resulting_epoch", wire_u64()),
        field("resulting_head", remote_head_schema()),
        field("consumed_at", wire_u64()),
    ]
}

fn disposable_delete_consumed_receipt_fields() -> Vec<Field> {
    vec![
        field("authorization_id", id()),
        field("volume_id", id()),
        field("disk_id", id()),
        field("cat_id", id()),
        field("delete_id", id()),
        field("prior_attachment_id", id()),
        field("resulting_epoch", wire_u64()),
        field("resulting_head", remote_head_schema()),
        field("consumed_at", wire_u64()),
    ]
}

fn volume_authorization_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("takeover", takeover_authorization_fields()),
            variant(
                "disposable_root_delete",
                disposable_delete_authorization_fields(),
            ),
        ],
    )
}

fn authorization_consumed_receipt_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("takeover", takeover_consumed_receipt_fields()),
            variant(
                "begin_disposable_delete",
                disposable_delete_consumed_receipt_fields(),
            ),
        ],
    )
}

fn authorization_state_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("unconsumed", vec![]),
            variant(
                "consumed",
                vec![field("receipt", authorization_consumed_receipt_schema())],
            ),
        ],
    )
}

fn authorization_record_schema() -> Schema {
    object(vec![
        field("authorization", volume_authorization_schema()),
        field("state", authorization_state_schema()),
    ])
}

fn delete_completion_receipt_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "normal",
                vec![
                    field("request", begin_delete_request_schema()),
                    field("deleting_epoch", wire_u64()),
                    field("deleting_head", remote_head_schema()),
                    field("completed_at", wire_u64()),
                ],
            ),
            variant(
                "disposable_root",
                vec![
                    field("disk_id", id()),
                    field("volume_id", id()),
                    field("delete_id", id()),
                    field("authorization_id", id()),
                    field("prior_attachment_id", id()),
                    field("deleting_epoch", wire_u64()),
                    field("deleting_head", remote_head_schema()),
                    field("completed_at", wire_u64()),
                ],
            ),
        ],
    )
}

fn runtime_volume_transition_evidence_request_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("session", session_binding_schema()),
        field("authorization_id", id()),
    ])
}

fn runtime_volume_transition_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "acquire",
                vec![field("request", volume_acquire_request_schema())],
            ),
            variant("release", vec![field("cleanup", cleanup_release_schema())]),
            variant(
                "delete_disposable_root",
                vec![field("authorization_id", id())],
            ),
            variant(
                "commit_initialized",
                vec![
                    field("filesystem", persistent_filesystem_binding_schema()),
                    field("new_remote_head", remote_head_schema()),
                ],
            ),
        ],
    )
}

fn runtime_volume_transition_request_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("session", session_binding_schema()),
        field("cat_id", id()),
        field("desired_revision", revision()),
        field("spec_digest", digest()),
        field("placement", assigned_placement_schema()),
        field("transition", runtime_volume_transition_schema()),
    ])
}

fn volume_lease_grant_schema() -> Schema {
    object(vec![
        field("volume_id", id()),
        field("attachment_id", id()),
        field("attachment_epoch", wire_u64()),
        field("size_bytes", number(1, MAX_WIRE_INTEGER)),
        field("durability", closed(&["strict", "relaxed"])),
        field("head", remote_head_schema()),
        field("lease_expires_at", wire_u64()),
        field("acquire_origin", acquire_origin_schema()),
    ])
}

fn runtime_volume_transition_outcome_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "lease_granted",
                vec![field("grant", volume_lease_grant_schema())],
            ),
            variant("released", vec![field("release", release_result_schema())]),
            variant(
                "disposable_root_deleting",
                vec![field(
                    "receipt",
                    object(disposable_delete_consumed_receipt_fields()),
                )],
            ),
            variant(
                "persistent_initialized",
                vec![field(
                    "receipt",
                    object(vec![
                        field("disk_id", id()),
                        field("volume_id", id()),
                        field("initialization_token", random_id()),
                        field("filesystem_uuid", random_id()),
                        field("expected_blank_head", remote_head_schema()),
                        field("initialized_head", remote_head_schema()),
                        field("initialized_at", wire_u64()),
                    ]),
                )],
            ),
        ],
    )
}

fn runtime_volume_transition_success_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("session", session_binding_schema()),
        field("cat_id", id()),
        field("desired_revision", revision()),
        field("spec_digest", digest()),
        field("placement", assigned_placement_schema()),
        field("outcome", runtime_volume_transition_outcome_schema()),
    ])
}

fn runtime_volume_transition_evidence_success_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("session", session_binding_schema()),
        field("authorization_id", id()),
        field("authorization", authorization_record_schema()),
        field("current_volume", nullable(volume_record_schema())),
        field(
            "delete_completion",
            nullable(delete_completion_receipt_schema()),
        ),
        field(
            "direct_successor_authorization",
            nullable(authorization_record_schema()),
        ),
    ])
}

fn runtime_volume_transition_error_detail_schema() -> Schema {
    union(
        "code",
        vec![
            variant("authentication_failed", vec![]),
            variant("identity_not_eligible", vec![]),
            variant(
                "http_request_rejected",
                vec![field(
                    "problem",
                    closed(&[
                        "method_not_allowed",
                        "query_not_allowed",
                        "content_type_not_allowed",
                        "content_encoding_not_allowed",
                        "authorization_not_allowed",
                        "accept_not_allowed",
                        "semantic_header_not_allowed",
                    ]),
                )],
            ),
            variant(
                "contract_error",
                vec![field("contract_error", contract_error_schema())],
            ),
            variant(
                "transition_precondition_failed",
                vec![
                    field("cat_id", id()),
                    field(
                        "problem",
                        closed(&[
                            "inventory_session_replaced",
                            "inventory_stale",
                            "volume_intent_mismatch",
                            "cleanup_evidence_mismatch",
                            "authorization_branch_conflict",
                        ]),
                    ),
                ],
            ),
            variant(
                "volume_authority_rejected",
                vec![
                    field("volume_id", id()),
                    field(
                        "reason",
                        closed(&[
                            "other_writer",
                            "fenced",
                            "stale_transition",
                            "invalid_lease_duration",
                            "epoch_exhausted",
                            "admin_busy",
                        ]),
                    ),
                ],
            ),
            variant(
                "volume_authorization_rejected",
                vec![
                    field("authorization_id", id()),
                    field(
                        "reason",
                        closed(&[
                            "invalid_authorization",
                            "invalid_lease_duration",
                            "snapshot_in_use",
                            "epoch_exhausted",
                        ]),
                    ),
                ],
            ),
            variant(
                "authorization_evidence_unavailable",
                vec![field("authorization_id", id())],
            ),
            variant("node_request_in_flight", vec![]),
            variant("temporarily_unavailable", vec![]),
            variant("internal", vec![]),
        ],
    )
}

fn runtime_volume_transition_error_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("error", runtime_volume_transition_error_detail_schema()),
        field("message", string(StringRule::Message)),
    ])
}

fn provision_root_image_request_schema() -> Schema {
    object(vec![
        field("provision_transition_id", random_id()),
        field("volume_id", id()),
        field("attachment_id", id()),
        field("attachment_epoch", wire_u64()),
        field("size_bytes", number(1, MAX_WIRE_INTEGER)),
        field("boot_image_digest", digest()),
        field("expected_blank_head", remote_head_schema()),
        field("expected_provisioned_head", remote_head_schema()),
    ])
}

fn provision_root_image_result_schema() -> Schema {
    object(vec![
        field("provision_transition_id", random_id()),
        field("volume_id", id()),
        field("attachment_id", id()),
        field("attachment_epoch", wire_u64()),
        field("resulting_head", remote_head_schema()),
    ])
}

fn provision_root_image_error_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "retryable",
                vec![
                    field("provision_transition_id", random_id()),
                    field("volume_id", id()),
                    field("attachment_id", id()),
                    field("attachment_epoch", wire_u64()),
                    field(
                        "problem",
                        closed(&[
                            "image_unavailable",
                            "object_store_unavailable",
                            "authority_unavailable",
                            "local_io_unavailable",
                        ]),
                    ),
                ],
            ),
            variant(
                "definite_conflict",
                vec![
                    field("provision_transition_id", random_id()),
                    field("volume_id", id()),
                    field("attachment_id", id()),
                    field("attachment_epoch", wire_u64()),
                    field(
                        "problem",
                        closed(&[
                            "request_binding",
                            "image_manifest",
                            "target_mismatch",
                            "local_state",
                            "immutable_object",
                        ]),
                    ),
                ],
            ),
        ],
    )
}

fn root_serving_handoff_record_identity_schema() -> Schema {
    object(vec![
        field("path", string(StringRule::HostPath)),
        field("device", wire_u64()),
        field("inode", number(1, MAX_WIRE_INTEGER)),
        field("length", number(1, MAX_WIRE_INTEGER)),
        field("content_sha256", digest()),
    ])
}

fn root_serving_handoff_schema() -> Schema {
    object(vec![
        field("predecessor_checkpoint_content_digest", digest()),
        field("record", root_serving_handoff_record_identity_schema()),
    ])
}

fn direct_authorized_attachment_identity_schema() -> Schema {
    object(vec![
        field("path", string(StringRule::HostPath)),
        field("device", wire_u64()),
        field("inode", number(1, MAX_WIRE_INTEGER)),
        field("length", number(1, MAX_WIRE_INTEGER)),
        field("content_sha256", digest()),
    ])
}

fn serving_authority_provenance_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "after_root_provision",
                vec![field("handoff", root_serving_handoff_schema())],
            ),
            variant(
                "direct_authorized_attachment",
                vec![
                    field(
                        "authorization",
                        direct_authorized_attachment_identity_schema(),
                    ),
                    field(
                        "purpose",
                        closed(&[
                            "existing_root",
                            "persistent_initialized",
                            "persistent_uninitialized",
                        ]),
                    ),
                ],
            ),
        ],
    )
}

fn serving_blockd_identity_schema() -> Schema {
    object(vec![
        field("scope_id", id()),
        field("control_socket_path", string(StringRule::HostPath)),
        field("data_directory", string(StringRule::HostPath)),
        field("executable_path", string(StringRule::HostPath)),
        field("process_identity_token", random_id()),
    ])
}

fn prepare_device_frontend_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "kernel_nbd",
                vec![
                    field("listener_socket_path", string(StringRule::HostPath)),
                    field("device_path", string(StringRule::HostPath)),
                    field("direct", Schema::Bool),
                ],
            ),
            variant(
                "vhost_user_blk",
                vec![
                    field("socket_path", string(StringRule::HostPath)),
                    field("queues", number(1, 64)),
                    field("queue_size", number(2, 32_768)),
                ],
            ),
        ],
    )
}

fn runtime_network_identity_schema() -> Schema {
    object(vec![
        field("network_config", network_config_schema()),
        field("tap_name", id()),
        field("ownership_token", random_id()),
    ])
}

fn runtime_launch_artifact_schema() -> Schema {
    object(vec![
        field("path", string(StringRule::HostPath)),
        field("length", number(1, MAX_WIRE_INTEGER)),
        field("content_sha256", digest()),
    ])
}

fn vmm_boot_provenance_schema() -> Schema {
    object(vec![
        field("vmm_executable", runtime_launch_artifact_schema()),
        field("kernel", runtime_launch_artifact_schema()),
        field("initramfs", nullable(runtime_launch_artifact_schema())),
        field("kernel_cmdline", string(StringRule::AsciiText)),
    ])
}

fn runtime_launch_identity_fields() -> Vec<Field> {
    vec![
        field("runtime_incarnation", random_id()),
        field("scope_id", id()),
        field("launcher_executable", runtime_launch_artifact_schema()),
        field("boot", vmm_boot_provenance_schema()),
        field("process_identity_token", random_id()),
        field("vcpus", number(1, u64::from(u32::MAX))),
        field("memory_bytes", number(1, MAX_WIRE_INTEGER)),
        field("boot_image_digest", digest()),
        field("guest_config_digest", digest()),
        field("api_socket_path", string(StringRule::HostPath)),
        field("vsock_socket_path", string(StringRule::HostPath)),
        field("guest_cid", number(3, u64::from(u32::MAX - 1))),
        field("memory_file_path", string(StringRule::HostPath)),
        field("serial_log_path", string(StringRule::HostPath)),
        field("vmm_log_path", string(StringRule::HostPath)),
        field("network", runtime_network_identity_schema()),
        field("devices", array(prepared_device_input_schema(), 64)),
    ]
}

fn runtime_launch_identity_schema() -> Schema {
    object(runtime_launch_identity_fields())
}

fn runtime_launch_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("absent", vec![]),
            variant(
                "present",
                vec![field("identity", runtime_launch_identity_schema())],
            ),
        ],
    )
}

fn prepared_device_input_schema() -> Schema {
    object(vec![
        field("volume_intent_id", id()),
        field("disk_id", id()),
        field("volume_id", id()),
        field("disk_kind", closed(&["root", "persistent"])),
        field("attachment_id", id()),
        field("attachment_epoch", number(1, MAX_WIRE_INTEGER)),
        field("acquire_origin", acquire_origin_schema()),
        field("expected_head", remote_head_schema()),
        field("size_bytes", number(1, MAX_WIRE_INTEGER)),
        field("durability", closed(&["strict", "relaxed"])),
        field("guest_device", guest_device_schema()),
        field("ownership_token", random_id()),
        field("serving_authority", serving_authority_provenance_schema()),
        field("serving_process", serving_blockd_identity_schema()),
        field("frontend", prepare_device_frontend_schema()),
    ])
}

fn reconcile_step_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("inspect_inventory", vec![field("inventory_epoch", epoch())]),
            variant("stable", vec![field("state", stable_state_schema())]),
            variant(
                "close_admission",
                vec![field("require_idle_attempt_id", nullable(random_id()))],
            ),
            variant(
                "close_gate",
                vec![field("endpoint_id", id()), field("route_epoch", epoch())],
            ),
            variant(
                "acquire_volume",
                vec![field("request", volume_acquire_request_schema())],
            ),
            variant(
                "provision_root_image",
                vec![
                    field("provision_transition_id", random_id()),
                    field("volume_id", id()),
                    field("attachment_id", id()),
                    field("attachment_epoch", wire_u64()),
                    field("scope_id", id()),
                    field("control_socket_path", string(StringRule::HostPath)),
                    field("data_directory", string(StringRule::HostPath)),
                    field("process_identity_token", random_id()),
                    field("size_bytes", number(1, MAX_WIRE_INTEGER)),
                    field("boot_image_digest", digest()),
                    field("expected_blank_head", remote_head_schema()),
                    field("expected_provisioned_head", remote_head_schema()),
                ],
            ),
            variant(
                "prepare_device",
                vec![field("devices", array(prepared_device_input_schema(), 64))],
            ),
            variant(
                "prepare_network",
                vec![
                    field("network", runtime_network_identity_schema()),
                    field("devices", array(prepared_device_input_schema(), 64)),
                ],
            ),
            variant(
                "format_filesystem",
                vec![field("filesystem", persistent_filesystem_binding_schema())],
            ),
            variant(
                "drain_initialization",
                vec![
                    field("filesystem", persistent_filesystem_binding_schema()),
                    field("local_generation", wire_u64()),
                    field("remote_generation", wire_u64()),
                ],
            ),
            variant(
                "commit_initialized",
                vec![
                    field("filesystem", persistent_filesystem_binding_schema()),
                    field("new_remote_head", remote_head_schema()),
                ],
            ),
            variant(
                "mount_filesystem",
                vec![
                    field("filesystem", persistent_filesystem_binding_schema()),
                    field("expected_head", remote_head_schema()),
                ],
            ),
            variant("start_runtime", runtime_launch_identity_fields()),
            variant(
                "drain_publish",
                vec![
                    field("volume_id", id()),
                    field("attachment_epoch", wire_u64()),
                    field("local_generation", wire_u64()),
                    field("remote_generation", wire_u64()),
                ],
            ),
            variant(
                "pause_runtime",
                vec![
                    field("runtime_incarnation", random_id()),
                    field("process_start_time_ticks", wire_u64()),
                ],
            ),
            variant(
                "snapshot_warm_runtime",
                vec![
                    field("runtime_incarnation", random_id()),
                    field("snapshot_id", id()),
                    field("temporary_path", string(StringRule::HostPath)),
                    field("source_heads", array(volume_head_schema(), 64)),
                ],
            ),
            variant(
                "stop_runtime",
                vec![
                    field("runtime_incarnation", random_id()),
                    field("process_start_time_ticks", wire_u64()),
                    field("scope_id", id()),
                ],
            ),
            variant(
                "cleanup_release",
                vec![field("cleanup", cleanup_release_schema())],
            ),
            variant(
                "delete_disposable_root",
                vec![field("authorization_id", id())],
            ),
            variant(
                "open_admission",
                vec![field("runtime_incarnation", random_id())],
            ),
            variant(
                "install_gate",
                vec![field("endpoint_id", id()), field("route_epoch", epoch())],
            ),
            variant("quarantined", vec![]),
        ],
    )
}

fn process_role_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("vmm", vec![field("runtime_incarnation", random_id())]),
            variant(
                "blockd",
                vec![
                    field("volume_id", id()),
                    field("attachment_id", id()),
                    field("attachment_epoch", wire_u64()),
                ],
            ),
        ],
    )
}

fn ownership_token_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("missing", vec![]),
            variant("corrupt", vec![field("raw_content_digest", digest())]),
            variant("valid", vec![field("ownership_token", random_id())]),
        ],
    )
}

fn control_handshake_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("unavailable", vec![]),
            variant("malformed", vec![field("raw_response_digest", digest())]),
            variant("verified", vec![]),
        ],
    )
}

fn observed_vm_shape_schema() -> Schema {
    object(vec![
        field("vcpus", number(1, u64::from(u32::MAX))),
        field("memory_bytes", number(1, MAX_WIRE_INTEGER)),
        field("boot_image_digest", digest()),
        field("guest_config_digest", digest()),
    ])
}

fn process_evidence_schema() -> Schema {
    object(vec![
        field("role", process_role_schema()),
        field("process_id", number(1, u64::from(u32::MAX))),
        field("process_start_time_ticks", wire_u64()),
        field("executable_path", string(StringRule::HostPath)),
        field("scope_id", id()),
        field("control_socket_path", string(StringRule::HostPath)),
        field("state", closed(&["running", "paused"])),
        field("ownership_token", ownership_token_schema()),
        field("control_handshake", control_handshake_schema()),
        field("observed_vm_shape", nullable(observed_vm_shape_schema())),
    ])
}

fn guest_transport_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("unavailable", vec![]),
            variant("malformed", vec![field("raw_response_digest", digest())]),
            variant(
                "vsock_ready",
                vec![
                    field("runtime_incarnation", random_id()),
                    field("guest_cid", number(3, u64::from(u32::MAX - 1))),
                    field(
                        "guest_port",
                        literal_number(u64::from(GUEST_AGENT_VSOCK_PORT_V1)),
                    ),
                    field("guest_agent_protocol_version", literal_number(1)),
                    field("guest_boot_id", random_id()),
                ],
            ),
        ],
    )
}

fn volume_authority_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("unavailable", vec![]),
            variant("absent", vec![]),
            variant(
                "unowned",
                vec![
                    field("attachment_epoch", wire_u64()),
                    field("head", remote_head_schema()),
                ],
            ),
            variant(
                "owned",
                vec![
                    field("attachment_id", id()),
                    field("attachment_epoch", wire_u64()),
                    field("head", remote_head_schema()),
                ],
            ),
            variant(
                "deleting",
                vec![
                    field("delete_id", id()),
                    field("attachment_epoch", wire_u64()),
                    field("head", remote_head_schema()),
                ],
            ),
        ],
    )
}

fn local_lineage_schema() -> Schema {
    object(vec![
        field("attachment_id", id()),
        field("attachment_epoch", wire_u64()),
        field("acquire_origin", acquire_origin_schema()),
        field("node_id", id()),
        field("placement_epoch", epoch()),
        field("local_durable_generation", wire_u64()),
        field("remote_durable_generation", wire_u64()),
        field("data_directory", string(StringRule::HostPath)),
        field("pending_pack_count", wire_u64()),
        field("fenced", Schema::Bool),
        field("state", closed(&["active", "released", "quarantined"])),
    ])
}

fn acquire_origin_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("normal", vec![field("transition_id", random_id())]),
            variant("takeover", vec![field("authorization_id", id())]),
        ],
    )
}

fn observed_device_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "kernel_nbd",
                vec![
                    field("guest_device", guest_device_schema()),
                    field("device_path", string(StringRule::HostPath)),
                    field("ownership_token", ownership_token_schema()),
                ],
            ),
            variant(
                "vhost_user_blk",
                vec![
                    field("guest_device", guest_device_schema()),
                    field("socket_path", string(StringRule::HostPath)),
                    field("ownership_token", ownership_token_schema()),
                ],
            ),
        ],
    )
}

fn observed_volume_schema() -> Schema {
    object(vec![
        field("volume_intent_id", nullable(id())),
        field("disk_id", nullable(id())),
        field("volume_id", id()),
        field("disk_kind", closed(&["root", "persistent", "unknown"])),
        field("size_bytes", nullable(number(1, MAX_WIRE_INTEGER))),
        field("durability", nullable(closed(&["strict", "relaxed"]))),
        field("authority", volume_authority_schema()),
        field("local_lineages", array(local_lineage_schema(), 8)),
        field("devices", array(observed_device_schema(), 16)),
    ])
}

fn observed_mount_schema() -> Schema {
    object(vec![
        field("volume_id", id()),
        field("guest_device", guest_device_schema()),
        field("source_path", string(StringRule::HostPath)),
        field("filesystem_uuid", random_id()),
        field("mount_path", string(StringRule::HostPath)),
        field("access", closed(&["read_write", "read_only"])),
        field("instance_count", number(1, MAX_WIRE_INTEGER)),
    ])
}

fn observed_network_schema() -> Schema {
    object(vec![
        field("kind", closed(&["isolated_ipv4"])),
        field("network_id", id()),
        field("guest_mac", string(StringRule::Mac)),
        field("guest_ipv4", string(StringRule::Ipv4)),
        field("prefix_length", literal_number(30)),
        field("gateway_ipv4", string(StringRule::Ipv4)),
        field("tap_name", id()),
        field("ownership_token", ownership_token_schema()),
    ])
}

fn warm_snapshot_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("absent", vec![]),
            variant(
                "present",
                vec![
                    field("snapshot_id", id()),
                    field("runtime_incarnation", random_id()),
                    field("path", string(StringRule::HostPath)),
                    field("file_size_bytes", wire_u64()),
                    field("file_digest", digest()),
                    field("source_heads", array(volume_head_schema(), 64)),
                    field("durable_rename_complete", Schema::Bool),
                ],
            ),
        ],
    )
}

fn route_binding_schema() -> Schema {
    object(vec![
        field("workspace_id", id()),
        field("endpoint_id", id()),
        field("hostname", string(StringRule::Hostname)),
        field("cat_id", id()),
        field("node_id", id()),
        field("runtime_incarnation", random_id()),
        field("route_epoch", epoch()),
        field("protocol", closed(&["http"])),
        field("target_port", number(1, u64::from(u16::MAX))),
    ])
}

fn observed_route_schema() -> Schema {
    object(vec![
        field("binding", route_binding_schema()),
        field("gate", closed(&["active", "closed"])),
        field("active_guards", number(0, u64::from(u32::MAX))),
        field("cancellation_pending", Schema::Bool),
        field("instance_count", number(1, MAX_WIRE_INTEGER)),
    ])
}

fn route_binding_evidence_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("missing", vec![]),
            variant("corrupt", vec![field("raw_content_digest", digest())]),
            variant("valid", vec![field("binding", route_binding_schema())]),
        ],
    )
}

fn residue_lineage_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("unreadable", vec![]),
            variant(
                "readable",
                vec![
                    field("attachment_id_hint", nullable(id())),
                    field("attachment_epoch_hint", nullable(wire_u64())),
                    field("local_durable_generation", wire_u64()),
                    field("remote_durable_generation", wire_u64()),
                    field("pending_pack_count", wire_u64()),
                    field("fenced", Schema::Bool),
                ],
            ),
        ],
    )
}

fn residue_checkpoint_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("corrupt", vec![field("raw_content_digest", digest())]),
            variant(
                "valid",
                vec![
                    field("content_digest", digest()),
                    field("version", projected_version()),
                    field("cat_id", id()),
                    field("node_id", id()),
                    field("placement_epoch", epoch()),
                    field("desired_revision", revision()),
                    field("spec_digest", digest()),
                    field("runtime_incarnation", nullable(random_id())),
                ],
            ),
        ],
    )
}

fn node_residue_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "process",
                vec![
                    field("process_id", number(1, u64::from(u32::MAX))),
                    field("process_start_time_ticks", wire_u64()),
                    field("executable_path", string(StringRule::HostPath)),
                    field("scope_id", nullable(id())),
                    field(
                        "control_socket_path",
                        nullable(string(StringRule::HostPath)),
                    ),
                    field("role_hint", nullable(process_role_schema())),
                    field("ownership_token", ownership_token_schema()),
                    field("control_handshake", control_handshake_schema()),
                ],
            ),
            variant(
                "systemd_scope",
                vec![
                    field("scope_id", id()),
                    field("cgroup_path", string(StringRule::HostPath)),
                    field("ownership_token", ownership_token_schema()),
                ],
            ),
            variant(
                "control_socket",
                vec![
                    field("socket_path", string(StringRule::HostPath)),
                    field("role_hint", nullable(process_role_schema())),
                    field("ownership_token", ownership_token_schema()),
                ],
            ),
            variant(
                "checkpoint_file",
                vec![
                    field("checkpoint_path", string(StringRule::HostPath)),
                    field("evidence", residue_checkpoint_schema()),
                ],
            ),
            variant(
                "kernel_nbd",
                vec![
                    field("volume_id_hint", nullable(id())),
                    field("guest_device", nullable(guest_device_schema())),
                    field("device_path", string(StringRule::HostPath)),
                    field("ownership_token", ownership_token_schema()),
                ],
            ),
            variant(
                "vhost_user_blk",
                vec![
                    field("volume_id_hint", nullable(id())),
                    field("guest_device", nullable(guest_device_schema())),
                    field("socket_path", string(StringRule::HostPath)),
                    field("ownership_token", ownership_token_schema()),
                ],
            ),
            variant(
                "network_tap",
                vec![
                    field("network_id_hint", nullable(id())),
                    field("tap_name", id()),
                    field("ownership_token", ownership_token_schema()),
                ],
            ),
            variant(
                "data_directory",
                vec![
                    field("volume_id_hint", nullable(id())),
                    field("data_directory", string(StringRule::HostPath)),
                    field("ownership_token", ownership_token_schema()),
                    field("lineage", residue_lineage_schema()),
                ],
            ),
            variant(
                "mount",
                vec![
                    field("volume_id_hint", nullable(id())),
                    field("source_path", string(StringRule::HostPath)),
                    field("mount_path", string(StringRule::HostPath)),
                    field("instance_count", number(1, MAX_WIRE_INTEGER)),
                ],
            ),
            variant(
                "warm_snapshot",
                vec![
                    field("snapshot_id_hint", nullable(id())),
                    field("path", string(StringRule::HostPath)),
                    field("file_size_bytes", wire_u64()),
                    field("file_digest", nullable(digest())),
                ],
            ),
            variant(
                "route_gate",
                vec![
                    field("binding", route_binding_evidence_schema()),
                    field("gate", closed(&["active", "closed"])),
                    field("active_guards", number(0, u64::from(u32::MAX))),
                    field("cancellation_pending", Schema::Bool),
                    field("instance_count", number(1, MAX_WIRE_INTEGER)),
                ],
            ),
        ],
    )
}

fn checkpoint_evidence_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "missing",
                vec![field("checkpoint_path", string(StringRule::HostPath))],
            ),
            variant(
                "corrupt",
                vec![
                    field("checkpoint_path", string(StringRule::HostPath)),
                    field("raw_content_digest", digest()),
                ],
            ),
            variant(
                "valid",
                vec![
                    field("checkpoint_path", string(StringRule::HostPath)),
                    field("content_digest", digest()),
                    field("version", projected_version()),
                    field("cat_id", id()),
                    field("node_id", id()),
                    field("desired_revision", revision()),
                    field("spec_digest", digest()),
                    field("placement_epoch", epoch()),
                    field("runtime_incarnation", nullable(random_id())),
                    field("runtime_launch", runtime_launch_schema()),
                    field("stable_state", nullable(stable_state_schema())),
                    field("step", reconcile_step_schema()),
                    field("require_idle", require_idle_schema()),
                    field("updated_at_unix_ms", wire_u64()),
                ],
            ),
        ],
    )
}

fn precondition_reason_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "busy",
                vec![
                    field("attempt_id", random_id()),
                    field("gate_closed", Schema::Bool),
                    field("platform_guards", number(0, u64::from(u32::MAX))),
                    field("endpoint_guards", array(endpoint_guard_schema(), 256)),
                ],
            ),
            variant(
                "must_be_cold",
                vec![field("observed_state", nullable(stable_state_schema()))],
            ),
            variant(
                "placement_rejected",
                vec![
                    field("node_id", id()),
                    field("placement_epoch", epoch()),
                    field(
                        "reason",
                        closed(&[
                            "insufficient_vcpus",
                            "insufficient_memory",
                            "unsupported_block_path",
                            "unsupported_network",
                            "unsupported_guest_capability",
                        ]),
                    ),
                ],
            ),
        ],
    )
}

fn blocked_reason_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "incomplete_inventory",
                vec![field(
                    "unavailable_sources",
                    array(
                        closed(&[
                            "checkpoint",
                            "systemd",
                            "process",
                            "control_socket",
                            "block_frontend",
                            "network",
                            "data_directory",
                            "pending_pack",
                            "warm_snapshot",
                            "metadata_store",
                            "guest_mount",
                        ]),
                        11,
                    ),
                )],
            ),
            variant(
                "superseded_by_another_node",
                vec![
                    field("volume_id", id()),
                    field("owner_node_id", id()),
                    field("attachment_id", id()),
                    field("attachment_epoch", wire_u64()),
                ],
            ),
            variant(
                "active_guards",
                vec![
                    field("platform_guards", number(0, u64::from(u32::MAX))),
                    field("endpoint_guards", array(endpoint_guard_schema(), 256)),
                ],
            ),
            variant(
                "volume_authority_unavailable",
                vec![field("volume_ids", array(id(), 64))],
            ),
            variant(
                "remote_durability_lag",
                vec![
                    field("volume_id", id()),
                    field("attachment_epoch", wire_u64()),
                    field("local_generation", wire_u64()),
                    field("remote_generation", wire_u64()),
                ],
            ),
            variant(
                "authorization_unavailable",
                vec![field("volume_id", id()), field("authorization_id", id())],
            ),
            variant(
                "host_rejoin_pending",
                vec![field("host_fence_event_id", id())],
            ),
            variant(
                "control_plane_unavailable",
                vec![field("last_desired_revision", nullable(revision()))],
            ),
            variant(
                "key_ring_unavailable",
                vec![
                    field("expected_version", epoch()),
                    field("expected_digest", digest()),
                    field("loaded_version", nullable(epoch())),
                    field("loaded_digest", nullable(digest())),
                ],
            ),
            variant(
                "root_image_unavailable",
                vec![field("boot_image_digest", digest())],
            ),
        ],
    )
}

fn attachment_identity_schema() -> Schema {
    object(vec![
        field("attachment_id", id()),
        field("attachment_epoch", wire_u64()),
    ])
}

fn ownership_resource_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "process",
                vec![
                    field("process_id", number(1, u64::from(u32::MAX))),
                    field("process_start_time_ticks", wire_u64()),
                ],
            ),
            variant(
                "kernel_nbd",
                vec![field("device_path", string(StringRule::HostPath))],
            ),
            variant(
                "vhost_user_blk",
                vec![field("socket_path", string(StringRule::HostPath))],
            ),
            variant("network_tap", vec![field("tap_name", id())]),
            variant(
                "data_directory",
                vec![field("data_directory", string(StringRule::HostPath))],
            ),
        ],
    )
}

fn quarantine_reason_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "spec_digest_conflict",
                vec![
                    field("desired_revision", revision()),
                    field("expected_digest", digest()),
                    field("observed_digest", digest()),
                ],
            ),
            variant(
                "checkpoint_corrupt",
                vec![field("raw_content_digest", digest())],
            ),
            variant(
                "runtime_identity_conflict",
                vec![
                    field("expected_incarnation", random_id()),
                    field("observed_incarnations", array(random_id(), 128)),
                ],
            ),
            variant(
                "duplicate_runtime",
                vec![field("observed_incarnations", array(random_id(), 128))],
            ),
            variant(
                "process_identity_conflict",
                vec![
                    field("role", process_role_schema()),
                    field("process_ids", array(number(1, u64::from(u32::MAX)), 128)),
                ],
            ),
            variant(
                "volume_identity_conflict",
                vec![
                    field("volume_id", id()),
                    field("expected_attachment_id", id()),
                    field("expected_attachment_epoch", wire_u64()),
                    field("observed_attachment_id", id()),
                    field("observed_attachment_epoch", wire_u64()),
                ],
            ),
            variant(
                "local_lineage_conflict",
                vec![
                    field("volume_id", id()),
                    field("data_directory", string(StringRule::HostPath)),
                    field("expected_attachment_id", id()),
                    field("observed_attachment_id", nullable(id())),
                ],
            ),
            variant(
                "local_lineage_corrupt",
                vec![
                    field("volume_id", id()),
                    field("data_directory", string(StringRule::HostPath)),
                    field(
                        "problem",
                        closed(&[
                            "identity_missing",
                            "pending_pack_gap",
                            "pending_pack_corrupt",
                        ]),
                    ),
                ],
            ),
            variant(
                "duplicate_writer",
                vec![
                    field("volume_id", id()),
                    field(
                        "observed_attachments",
                        array(attachment_identity_schema(), 64),
                    ),
                ],
            ),
            variant(
                "duplicate_device",
                vec![
                    field("volume_id", id()),
                    field("observed_device_count", wire_u64()),
                ],
            ),
            variant(
                "duplicate_mount",
                vec![
                    field("volume_id", id()),
                    field("mount_path", string(StringRule::HostPath)),
                    field("observed_instance_count", wire_u64()),
                ],
            ),
            variant(
                "duplicate_network",
                vec![
                    field("network_id", id()),
                    field("observed_tap_count", wire_u64()),
                ],
            ),
            variant(
                "duplicate_route",
                vec![
                    field("endpoint_id", id()),
                    field("observed_instance_count", wire_u64()),
                ],
            ),
            variant(
                "invalid_ownership_token",
                vec![
                    field("resource", ownership_resource_schema()),
                    field("evidence", ownership_token_schema()),
                ],
            ),
            variant(
                "unattributed_node_residue",
                vec![field("residue", node_residue_schema())],
            ),
            variant(
                "filesystem_identity_conflict",
                vec![
                    field("volume_id", id()),
                    field("expected_filesystem_uuid", random_id()),
                    field("observed_filesystem_uuid", nullable(random_id())),
                ],
            ),
            variant(
                "unknown_persistent_disk",
                vec![
                    field("volume_id", id()),
                    field("data_directory", nullable(string(StringRule::HostPath))),
                ],
            ),
            variant(
                "warm_snapshot_conflict",
                vec![
                    field("snapshot_id", id()),
                    field("expected_digest", digest()),
                    field("observed_digest", nullable(digest())),
                ],
            ),
            variant(
                "route_gate_conflict",
                vec![
                    field("endpoint_id", id()),
                    field("expected_binding", route_binding_schema()),
                    field("observed_binding", route_binding_schema()),
                ],
            ),
            variant(
                "root_provision_conflict",
                vec![
                    field("volume_id", id()),
                    field("provision_transition_id", random_id()),
                    field(
                        "problem",
                        closed(&[
                            "control_process_identity",
                            "request_binding",
                            "image_manifest",
                            "target_mismatch",
                            "local_state",
                            "immutable_object",
                            "head_conflict",
                        ]),
                    ),
                ],
            ),
        ],
    )
}

fn degraded_reason_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "source_unavailable",
                vec![
                    field(
                        "sources",
                        array(
                            closed(&[
                                "control_store",
                                "metadata_store",
                                "checkpoint",
                                "systemd",
                                "process",
                                "control_socket",
                                "block_frontend",
                                "network",
                                "data_directory",
                                "pending_pack",
                                "warm_snapshot",
                                "guest_mount",
                            ]),
                            12,
                        ),
                    ),
                    field("since_unix_ms", wire_u64()),
                ],
            ),
            variant(
                "attestation_refresh_failed",
                vec![
                    field("inventory_epoch", epoch()),
                    field("since_unix_ms", wire_u64()),
                ],
            ),
        ],
    )
}

fn data_loss_reason_schema() -> Schema {
    union(
        "kind",
        vec![variant(
            "remote_tail_unavailable",
            vec![
                field("volume_id", id()),
                field("attachment_id", id()),
                field("attachment_epoch", wire_u64()),
                field("local_generation", wire_u64()),
                field("remote_generation", wire_u64()),
                field("host_fence_event_id", id()),
            ],
        )],
    )
}

fn condition_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "ready",
                vec![field(
                    "reason",
                    union(
                        "kind",
                        vec![variant(
                            "postcondition_satisfied",
                            vec![field("target", runtime_target_schema())],
                        )],
                    ),
                )],
            ),
            variant(
                "progressing",
                vec![field(
                    "reason",
                    union(
                        "kind",
                        vec![variant(
                            "reconcile_step",
                            vec![field("step", reconcile_step_schema())],
                        )],
                    ),
                )],
            ),
            variant("blocked", vec![field("reason", blocked_reason_schema())]),
            variant(
                "precondition_failed",
                vec![field("reason", precondition_reason_schema())],
            ),
            variant("degraded", vec![field("reason", degraded_reason_schema())]),
            variant(
                "quarantined",
                vec![field("reason", quarantine_reason_schema())],
            ),
            variant(
                "data_loss_possible",
                vec![field("reason", data_loss_reason_schema())],
            ),
        ],
    )
}

fn applied_desired_schema() -> Schema {
    object(vec![
        field("desired_revision", revision()),
        field("spec_digest", digest()),
        field("placement", assigned_placement_schema()),
        field("target", runtime_target_schema()),
    ])
}

fn observed_runtime_schema() -> Schema {
    object(vec![
        field("cat_id", id()),
        field("applied_desired", nullable(applied_desired_schema())),
        field("runtime_incarnation", nullable(random_id())),
        field("stable_state", nullable(stable_state_schema())),
        field("step", reconcile_step_schema()),
        field("checkpoint", checkpoint_evidence_schema()),
        field("processes", array(process_evidence_schema(), 128)),
        field("volumes", array(observed_volume_schema(), 64)),
        field("mounts", array(observed_mount_schema(), 64)),
        field("networks", array(observed_network_schema(), 16)),
        field("guest_transport", guest_transport_schema()),
        field("warm_snapshot", warm_snapshot_schema()),
        field("lifecycle_admission", closed(&["open", "closed"])),
        field("routes", array(observed_route_schema(), 512)),
        field("platform_guards", number(0, u64::from(u32::MAX))),
        field("conditions", array(condition_schema(), 64)),
    ])
}

fn runtime_checkpoint_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("cat_id", id()),
        field("node_id", id()),
        field("placement_epoch", epoch()),
        field("desired_revision", revision()),
        field("spec_digest", digest()),
        field("runtime_incarnation", nullable(random_id())),
        field("runtime_launch", runtime_launch_schema()),
        field("stable_state", nullable(stable_state_schema())),
        field("step", reconcile_step_schema()),
        field("processes", array(process_evidence_schema(), 128)),
        field("volumes", array(observed_volume_schema(), 64)),
        field("mounts", array(observed_mount_schema(), 64)),
        field("networks", array(observed_network_schema(), 16)),
        field("guest_transport", guest_transport_schema()),
        field("warm_snapshot", warm_snapshot_schema()),
        field("lifecycle_admission", closed(&["open", "closed"])),
        field(
            "route_gates",
            array(
                object(vec![
                    field("binding", route_binding_schema()),
                    field("gate", closed(&["active", "closed"])),
                ]),
                256,
            ),
        ),
        field("require_idle", require_idle_schema()),
        field("updated_at_unix_ms", wire_u64()),
    ])
}

fn node_observation_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("observation_id", random_id()),
        field("node_id", id()),
        field("node_boot_id", random_id()),
        field("agent_instance_id", random_id()),
        field("agent_session_epoch", epoch()),
        field("heartbeat_sequence", sequence()),
        field("observed_at_unix_ms", wire_u64()),
        field("complete_inventory", Schema::Bool),
        field("inventory_epoch", epoch()),
        field("inventory_digest", nullable(digest())),
        field("inventory_read_position", nullable(sequence())),
        field("key_ring_version", nullable(epoch())),
        field("key_ring_digest", nullable(digest())),
        field("loaded_kids", array(string(StringRule::KeyId), 64)),
        field("runtimes", array(observed_runtime_schema(), 1024)),
        field("residue", array(node_residue_schema(), 4096)),
    ])
}

fn operation_failure_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "precondition_failed",
                vec![field("reason", precondition_reason_schema())],
            ),
            variant(
                "host_lost",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("host_fence_event_id", id()),
                ],
            ),
            variant(
                "quarantined",
                vec![field("reason", quarantine_reason_schema())],
            ),
        ],
    )
}

fn operation_terminal_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "succeeded",
                vec![
                    field(
                        "result",
                        object(vec![
                            field("observation_id", random_id()),
                            field("node_id", id()),
                            field("agent_session_epoch", epoch()),
                            field("heartbeat_sequence", sequence()),
                            field("observed_target", runtime_target_schema()),
                            field("runtime_incarnation", nullable(random_id())),
                        ]),
                    ),
                    field("completed_at_unix_ms", wire_u64()),
                ],
            ),
            variant(
                "failed",
                vec![
                    field("error", operation_failure_schema()),
                    field("completed_at_unix_ms", wire_u64()),
                ],
            ),
            variant(
                "superseded",
                vec![
                    field("superseded_by_revision", revision()),
                    field("superseded_by_operation_id", id()),
                    field("completed_at_unix_ms", wire_u64()),
                ],
            ),
        ],
    )
}

fn operation_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("operation_id", id()),
        field("workspace_id", id()),
        field("cat_id", id()),
        field("desired_revision", revision()),
        field("desired_spec_digest", digest()),
        field("placement", assigned_placement_schema()),
        field("target", runtime_target_schema()),
        field(
            "phase",
            closed(&["pending", "succeeded", "failed", "superseded"]),
        ),
        field("terminal", nullable(operation_terminal_schema())),
        field("created_at_unix_ms", wire_u64()),
        field("updated_at_unix_ms", wire_u64()),
    ])
}

fn contract_name_schema() -> Schema {
    closed(&[
        "node_identity",
        "node_placement_policy",
        "runtime_node_authority_apply",
        "runtime_node_authority_apply_result",
        "runtime_provisioner_trust_bundle",
        "runtime_provisioner_active_set",
        "runtime_node_authority_apply_record",
        "agent_registration_attempt",
        "agent_session",
        "guest_runtime_profile_receipt",
        "admission_inventory_attestation",
        "desired_read_request",
        "desired_read_snapshot",
        "desired_runtime_spec",
        "runtime_checkpoint",
        "node_cleanup_checkpoint",
        "node_observation",
        "observation_acceptance",
        "runtime_spine_error",
        "runtime_volume_transition_request",
        "runtime_volume_transition_success",
        "runtime_volume_transition_evidence_request",
        "runtime_volume_transition_evidence_success",
        "runtime_volume_transition_error",
        "operation",
        "contract_error",
    ])
}

fn registration_binding_schema() -> Schema {
    object(vec![
        field("immutable_host_id", id()),
        field("node_boot_id", random_id()),
        field("agent_instance_id", random_id()),
        field("guest_config_digest", digest()),
        field("expected_agent_session_epoch", nullable(epoch())),
    ])
}

fn contract_error_detail_schema() -> Schema {
    union(
        "code",
        vec![
            variant("missing_agent_session", vec![field("node_id", id())]),
            variant(
                "stale_session",
                vec![
                    field("node_id", id()),
                    field("presented_agent_session_epoch", epoch()),
                    field("current_agent_session_epoch", epoch()),
                ],
            ),
            variant(
                "wrong_session",
                vec![
                    field("expected", session_binding_schema()),
                    field("presented", session_binding_schema()),
                ],
            ),
            variant(
                "registration_attempt_conflict",
                vec![
                    field("node_id", id()),
                    field("registration_attempt_id", random_id()),
                    field("expected", registration_binding_schema()),
                    field("presented", registration_binding_schema()),
                ],
            ),
            variant(
                "guest_config_mismatch",
                vec![
                    field("node_id", id()),
                    field("expected_guest_config_digest", digest()),
                    field("presented_guest_config_digest", digest()),
                ],
            ),
            variant(
                "stale_observation_sequence",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("presented_heartbeat_sequence", sequence()),
                    field("last_accepted_heartbeat_sequence", sequence()),
                ],
            ),
            variant(
                "observation_sequence_conflict",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("heartbeat_sequence", sequence()),
                    field("accepted_observation_id", random_id()),
                    field("presented_observation_id", random_id()),
                ],
            ),
            variant(
                "session_expired",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("lease_deadline_unix_ms", wire_u64()),
                    field("server_time_unix_ms", wire_u64()),
                ],
            ),
            variant(
                "stale_desired_read_sequence",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("presented_request_sequence", sequence()),
                    field("last_request_sequence", sequence()),
                ],
            ),
            variant(
                "wrong_desired_read_sequence",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("expected_request_sequence", sequence()),
                    field("presented_request_sequence", sequence()),
                ],
            ),
            variant(
                "desired_read_in_progress",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("request_sequence", sequence()),
                    field("read_position", sequence()),
                    field("expires_at_unix_ms", wire_u64()),
                ],
            ),
            variant(
                "assigned_set_limit_exceeded",
                vec![
                    field("node_id", id()),
                    field("limit", closed(&["desired_specs", "wire_bytes"])),
                    field("maximum", wire_u64()),
                    field("observed_at_least", wire_u64()),
                ],
            ),
            variant(
                "missing_inventory_read_position",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                ],
            ),
            variant(
                "stale_inventory_read_position",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("presented_read_position", sequence()),
                    field("current_read_position", sequence()),
                ],
            ),
            variant(
                "wrong_inventory_read_position",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("current_read_position", sequence()),
                    field("presented_read_position", sequence()),
                ],
            ),
            variant(
                "inventory_read_position_expired",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("read_position", sequence()),
                    field("expires_at_unix_ms", wire_u64()),
                    field("server_time_unix_ms", wire_u64()),
                ],
            ),
            variant(
                "inventory_read_position_consumed",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("read_position", sequence()),
                    field("accepted_observation_id", random_id()),
                    field("accepted_heartbeat_sequence", sequence()),
                ],
            ),
            variant(
                "assigned_set_changed",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("read_position", sequence()),
                ],
            ),
            variant(
                "incomplete_assigned_inventory",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("read_position", sequence()),
                    field("missing_cat_id", id()),
                ],
            ),
            variant(
                "assigned_runtime_binding_mismatch",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("read_position", sequence()),
                    field("cat_id", id()),
                    field("expected", applied_desired_schema()),
                    field("presented", nullable(applied_desired_schema())),
                ],
            ),
            variant(
                "missing_inventory_attestation",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                ],
            ),
            variant(
                "stale_inventory_epoch",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("presented_inventory_epoch", epoch()),
                    field("current_inventory_epoch", epoch()),
                ],
            ),
            variant(
                "wrong_inventory_epoch",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("expected_inventory_epoch", epoch()),
                    field("presented_inventory_epoch", epoch()),
                ],
            ),
            variant(
                "partial_cat_not_in_full_inventory",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("inventory_epoch", epoch()),
                    field("cat_id", id()),
                ],
            ),
            variant(
                "stale_revision",
                vec![
                    field("cat_id", id()),
                    field("presented_revision", revision()),
                    field("current_revision", revision()),
                ],
            ),
            variant(
                "wrong_revision",
                vec![
                    field("cat_id", id()),
                    field("expected_revision", revision()),
                    field("presented_revision", revision()),
                ],
            ),
            variant(
                "revision_digest_conflict",
                vec![
                    field("cat_id", id()),
                    field("desired_revision", revision()),
                    field("expected_digest", digest()),
                    field("presented_digest", digest()),
                ],
            ),
            variant(
                "wrong_placement",
                vec![
                    field("cat_id", id()),
                    field("desired_revision", revision()),
                    field("expected", assigned_placement_schema()),
                    field("presented", assigned_placement_schema()),
                ],
            ),
            variant(
                "unsupported_version",
                vec![
                    field("contract", contract_name_schema()),
                    field("supported_version", literal_number(1)),
                    field("presented_version", version()),
                ],
            ),
            variant(
                "malformed_payload",
                vec![
                    field("contract", contract_name_schema()),
                    field("json_pointer", string(StringRule::JsonPointer)),
                    field(
                        "problem",
                        closed(&[
                            "invalid_utf8",
                            "invalid_json",
                            "missing_field",
                            "unknown_field",
                            "duplicate_field",
                            "invalid_type",
                            "invalid_value",
                            "duplicate_identity",
                            "non_canonical_order",
                        ]),
                    ),
                ],
            ),
            variant(
                "limit_exceeded",
                vec![
                    field("contract", contract_name_schema()),
                    field("json_pointer", string(StringRule::JsonPointer)),
                    field("limit", closed(&["wire_bytes", "array_items"])),
                    field("maximum", wire_u64()),
                    field("observed_at_least", wire_u64()),
                ],
            ),
            variant(
                "idempotency_conflict",
                vec![
                    field("authenticated_workspace_id", id()),
                    field("canonical_route", string(StringRule::AsciiText)),
                    field("idempotency_key", string(StringRule::AsciiText)),
                    field("expected_request_fingerprint", digest()),
                    field("presented_request_fingerprint", digest()),
                ],
            ),
        ],
    )
}

fn contract_error_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("error", contract_error_detail_schema()),
        field("message", string(StringRule::Message)),
    ])
}

fn node_identity_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("node_id", id()),
        field("immutable_host_id", id()),
        field("credential_id", id()),
        field("credential_binding", credential_binding_schema()),
        field("state_path_id", id()),
        field("state", closed(&["provisioned", "retired"])),
    ])
}

fn runtime_placement_capabilities_schema() -> Schema {
    object(vec![
        field("vmm", closed(&["cloud_hypervisor"])),
        field("block_frontend", closed(&["kernel_nbd", "vhost_user_blk"])),
        field("guest_network", closed(&["isolated_ipv4"])),
        field("guest_transport", closed(&["vsock"])),
        field("guest_agent_protocol_version", literal_number(1)),
        field("guest_config_digest", digest()),
    ])
}

fn guest_ipv4_pool_schema() -> Schema {
    object(vec![
        field("kind", closed(&["private_ipv4_16"])),
        field("network_address", string(StringRule::Ipv4)),
        field("prefix_length", literal_number(16)),
    ])
}

fn node_placement_policy_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("node_id", id()),
        field("policy_revision", epoch()),
        field("scheduling_state", closed(&["cordoned", "schedulable"])),
        field("allocatable_vcpus", number(1, u64::from(u32::MAX))),
        field("allocatable_memory_bytes", number(1, MAX_WIRE_INTEGER)),
        field("capabilities", runtime_placement_capabilities_schema()),
        field("guest_ipv4_pool", guest_ipv4_pool_schema()),
        field(
            "node_transport_target",
            string(StringRule::NodeTransportTarget),
        ),
    ])
}

fn public_key_credential_binding_schema() -> Schema {
    union(
        "kind",
        vec![variant(
            "public_key",
            vec![field("public_key_spki_sha256", digest())],
        )],
    )
}

fn runtime_node_authority_mutation_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "provision",
                vec![
                    field("node_identity", node_identity_schema()),
                    field("placement_policy", node_placement_policy_schema()),
                ],
            ),
            variant(
                "update_policy",
                vec![
                    field("expected_policy_revision", epoch()),
                    field("placement_policy", node_placement_policy_schema()),
                ],
            ),
            variant(
                "rotate_credential",
                vec![
                    field("expected_policy_revision", epoch()),
                    field("expected_credential_id", id()),
                    field(
                        "expected_credential_binding",
                        public_key_credential_binding_schema(),
                    ),
                    field("new_credential_id", id()),
                    field(
                        "new_credential_binding",
                        public_key_credential_binding_schema(),
                    ),
                ],
            ),
            variant(
                "retire",
                vec![
                    field("expected_policy_revision", epoch()),
                    field("expected_credential_id", id()),
                    field(
                        "expected_credential_binding",
                        public_key_credential_binding_schema(),
                    ),
                ],
            ),
        ],
    )
}

fn runtime_node_authority_apply_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("apply_id", random_id()),
        field("node_id", id()),
        field("mutation", runtime_node_authority_mutation_schema()),
    ])
}

fn runtime_node_authority_apply_result_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("apply_id", random_id()),
        field("node_id", id()),
        field(
            "outcome",
            closed(&[
                "provisioned",
                "policy_updated",
                "credential_rotated",
                "retired",
            ]),
        ),
        field("identity_state", closed(&["provisioned", "retired"])),
        field("policy_revision", epoch()),
    ])
}

fn runtime_provisioner_credential_schema() -> Schema {
    object(vec![
        field("credential_id", id()),
        field("public_key_spki", base64url_no_pad()),
    ])
}

fn runtime_provisioner_expected_previous_schema() -> Schema {
    object(vec![
        field("trust_revision", epoch()),
        field("active_set_sha256", digest()),
    ])
}

fn runtime_provisioner_trust_bundle_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("deployment_id", id()),
        field("trust_revision", epoch()),
        field(
            "expected_previous",
            nullable(runtime_provisioner_expected_previous_schema()),
        ),
        field(
            "credentials",
            array(runtime_provisioner_credential_schema(), 4),
        ),
    ])
}

fn runtime_provisioner_active_set_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("deployment_id", id()),
        field(
            "credentials",
            array(runtime_provisioner_credential_schema(), 4),
        ),
    ])
}

fn agent_registration_attempt_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("node_id", id()),
        field("immutable_host_id", id()),
        field("node_boot_id", random_id()),
        field("agent_instance_id", random_id()),
        field("registration_attempt_id", random_id()),
        field("guest_config_digest", digest()),
        field("expected_agent_session_epoch", nullable(epoch())),
    ])
}

fn agent_session_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("node_id", id()),
        field("immutable_host_id", id()),
        field("node_boot_id", random_id()),
        field("agent_instance_id", random_id()),
        field("agent_session_epoch", epoch()),
        field("registration_attempt_id", random_id()),
        field("guest_config_digest", digest()),
        field("lease_deadline_unix_ms", wire_u64()),
    ])
}

fn guest_runtime_profile_receipt_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("kernel_digest", digest()),
        field("initramfs_digest", nullable(digest())),
        field("kernel_cmdline", string(StringRule::AsciiText)),
        field("guest_agent_protocol_version", literal_number(1)),
    ])
}

fn admission_attestation_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("node_id", id()),
        field("agent_session_epoch", epoch()),
        field("inventory_epoch", epoch()),
        field("inventory_digest", digest()),
        field("inventory_read_position", sequence()),
        field("accepted_at_unix_ms", wire_u64()),
    ])
}

fn desired_read_request_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("session", session_binding_schema()),
        field("request_sequence", sequence()),
    ])
}

fn desired_read_snapshot_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("session", session_binding_schema()),
        field("request_sequence", sequence()),
        field("read_position", sequence()),
        field("issued_at_unix_ms", wire_u64()),
        field("expires_at_unix_ms", wire_u64()),
        field("desired_specs", array(desired_runtime_spec_schema(), 1024)),
    ])
}

fn observation_inventory_acceptance_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "full",
                vec![field("attestation", admission_attestation_schema())],
            ),
            variant("partial", vec![field("inventory_epoch", epoch())]),
        ],
    )
}

fn observation_acceptance_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("session", session_binding_schema()),
        field("observation_id", random_id()),
        field("heartbeat_sequence", sequence()),
        field("accepted_at_unix_ms", wire_u64()),
        field("lease_deadline_unix_ms", wire_u64()),
        field("inventory", observation_inventory_acceptance_schema()),
    ])
}

fn runtime_spine_error_detail_schema() -> Schema {
    union(
        "code",
        vec![
            variant("authentication_failed", vec![]),
            variant("identity_not_eligible", vec![]),
            variant(
                "http_request_rejected",
                vec![field(
                    "problem",
                    closed(&[
                        "method_not_allowed",
                        "query_not_allowed",
                        "content_type_not_allowed",
                        "content_encoding_not_allowed",
                        "authorization_not_allowed",
                        "accept_not_allowed",
                        "semantic_header_not_allowed",
                    ]),
                )],
            ),
            variant(
                "contract_error",
                vec![field("contract_error", contract_error_schema())],
            ),
            variant("node_request_in_flight", vec![]),
            variant("temporarily_unavailable", vec![]),
            variant("internal", vec![]),
        ],
    )
}

fn runtime_spine_error_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("error", runtime_spine_error_detail_schema()),
        field("message", string(StringRule::Message)),
    ])
}

fn node_cleanup_checkpoint_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("node_id", id()),
        field("cleanup", cleanup_release_schema()),
    ])
}

// These schemas are immutable protocol metadata. Constructing the deeply nested
// NodeObservation tree on every heartbeat would put avoidable allocation on the
// hot path, so each explicit decoder shares one lazily initialized tree.
static NODE_IDENTITY_SCHEMA: LazyLock<Schema> = LazyLock::new(node_identity_schema);
static NODE_PLACEMENT_POLICY_SCHEMA: LazyLock<Schema> = LazyLock::new(node_placement_policy_schema);
static RUNTIME_NODE_AUTHORITY_APPLY_SCHEMA: LazyLock<Schema> =
    LazyLock::new(runtime_node_authority_apply_schema);
static RUNTIME_NODE_AUTHORITY_APPLY_RESULT_SCHEMA: LazyLock<Schema> =
    LazyLock::new(runtime_node_authority_apply_result_schema);
static RUNTIME_PROVISIONER_TRUST_BUNDLE_SCHEMA: LazyLock<Schema> =
    LazyLock::new(runtime_provisioner_trust_bundle_schema);
static RUNTIME_PROVISIONER_ACTIVE_SET_SCHEMA: LazyLock<Schema> =
    LazyLock::new(runtime_provisioner_active_set_schema);
static AGENT_REGISTRATION_ATTEMPT_SCHEMA: LazyLock<Schema> =
    LazyLock::new(agent_registration_attempt_schema);
static AGENT_SESSION_SCHEMA: LazyLock<Schema> = LazyLock::new(agent_session_schema);
static GUEST_RUNTIME_PROFILE_RECEIPT_SCHEMA: LazyLock<Schema> =
    LazyLock::new(guest_runtime_profile_receipt_schema);
static ADMISSION_ATTESTATION_SCHEMA: LazyLock<Schema> = LazyLock::new(admission_attestation_schema);
static DESIRED_READ_REQUEST_SCHEMA: LazyLock<Schema> = LazyLock::new(desired_read_request_schema);
static DESIRED_READ_SNAPSHOT_SCHEMA: LazyLock<Schema> = LazyLock::new(desired_read_snapshot_schema);
static DESIRED_RUNTIME_SPEC_SCHEMA: LazyLock<Schema> = LazyLock::new(desired_runtime_spec_schema);
static RUNTIME_CHECKPOINT_SCHEMA: LazyLock<Schema> = LazyLock::new(runtime_checkpoint_schema);
static NODE_CLEANUP_CHECKPOINT_SCHEMA: LazyLock<Schema> =
    LazyLock::new(node_cleanup_checkpoint_schema);
static NODE_OBSERVATION_SCHEMA: LazyLock<Schema> = LazyLock::new(node_observation_schema);
static OBSERVATION_ACCEPTANCE_SCHEMA: LazyLock<Schema> =
    LazyLock::new(observation_acceptance_schema);
static RUNTIME_SPINE_ERROR_SCHEMA: LazyLock<Schema> = LazyLock::new(runtime_spine_error_schema);
static RUNTIME_VOLUME_TRANSITION_REQUEST_SCHEMA: LazyLock<Schema> =
    LazyLock::new(runtime_volume_transition_request_schema);
static RUNTIME_VOLUME_TRANSITION_SUCCESS_SCHEMA: LazyLock<Schema> =
    LazyLock::new(runtime_volume_transition_success_schema);
static RUNTIME_VOLUME_TRANSITION_EVIDENCE_REQUEST_SCHEMA: LazyLock<Schema> =
    LazyLock::new(runtime_volume_transition_evidence_request_schema);
static RUNTIME_VOLUME_TRANSITION_EVIDENCE_SUCCESS_SCHEMA: LazyLock<Schema> =
    LazyLock::new(runtime_volume_transition_evidence_success_schema);
static RUNTIME_VOLUME_TRANSITION_ERROR_SCHEMA: LazyLock<Schema> =
    LazyLock::new(runtime_volume_transition_error_schema);
static OPERATION_SCHEMA: LazyLock<Schema> = LazyLock::new(operation_schema);
static CONTRACT_ERROR_SCHEMA: LazyLock<Schema> = LazyLock::new(contract_error_schema);
static PROVISION_ROOT_IMAGE_REQUEST_SCHEMA: LazyLock<Schema> =
    LazyLock::new(provision_root_image_request_schema);
static PROVISION_ROOT_IMAGE_RESULT_SCHEMA: LazyLock<Schema> =
    LazyLock::new(provision_root_image_result_schema);
static PROVISION_ROOT_IMAGE_ERROR_SCHEMA: LazyLock<Schema> =
    LazyLock::new(provision_root_image_error_schema);

fn provision_payload_error(error: PayloadValidationError) -> ProvisionRootImageWireDecodeError {
    match error {
        PayloadValidationError::Malformed {
            json_pointer,
            problem,
        } => ProvisionRootImageWireDecodeError::Malformed {
            json_pointer,
            problem,
        },
        PayloadValidationError::LimitExceeded {
            limit: LimitKind::WireBytes,
            maximum,
            ..
        } => ProvisionRootImageWireDecodeError::WireBytesLimitExceeded {
            maximum: WireU64::new(maximum as u64).expect("local wire limit fits the wire range"),
            observed_at_least: WireU64::new(maximum as u64 + 1)
                .expect("local wire limit plus one fits the wire range"),
        },
        // Local provision schemas contain no arrays or version field. Keep a
        // closed fail-safe mapping here so a future private schema edit cannot
        // leak a runtime ContractError or panic at an untrusted-input boundary.
        PayloadValidationError::LimitExceeded { json_pointer, .. } => {
            ProvisionRootImageWireDecodeError::Malformed {
                json_pointer,
                problem: MalformedProblem::InvalidValue,
            }
        }
        PayloadValidationError::UnsupportedVersion(_) => {
            ProvisionRootImageWireDecodeError::Malformed {
                json_pointer: JsonPointer::new("").expect("root pointer is valid"),
                problem: MalformedProblem::InvalidValue,
            }
        }
    }
}

fn decode_provision_payload<T>(
    bytes: &[u8],
    maximum_bytes: usize,
    schema: &Schema,
) -> Result<T, ProvisionRootImageWireDecodeError>
where
    T: DeserializeOwned,
{
    let input =
        validate_payload(bytes, maximum_bytes, schema, false).map_err(provision_payload_error)?;
    serde_json::from_str(input).map_err(|_| ProvisionRootImageWireDecodeError::Malformed {
        json_pointer: JsonPointer::new("").expect("root pointer is valid"),
        problem: MalformedProblem::InvalidValue,
    })
}

fn provision_cross_error(candidate: Candidate) -> ProvisionRootImageWireDecodeError {
    ProvisionRootImageWireDecodeError::Malformed {
        json_pointer: render_pointer(&candidate.path),
        problem: candidate.problem,
    }
}

fn encode_provision_payload<T>(
    value: &T,
    decode: fn(&[u8]) -> Result<T, ProvisionRootImageWireDecodeError>,
) -> Result<Vec<u8>, ProvisionRootImageWireDecodeError>
where
    T: Serialize,
{
    let value =
        serde_json::to_value(value).map_err(|_| ProvisionRootImageWireDecodeError::Malformed {
            json_pointer: JsonPointer::new("").expect("root pointer is valid"),
            problem: MalformedProblem::InvalidValue,
        })?;
    let bytes = value_bytes(&value);
    decode(&bytes)?;
    Ok(bytes)
}

pub fn decode_provision_root_image_request(
    bytes: &[u8],
) -> Result<ProvisionRootImageRequest, ProvisionRootImageWireDecodeError> {
    let request: ProvisionRootImageRequest = decode_provision_payload(
        bytes,
        PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES,
        &PROVISION_ROOT_IMAGE_REQUEST_SCHEMA,
    )?;
    let mut cross = Vec::new();
    collect_remote_head_cross(
        &request.expected_blank_head,
        &path(&["expected_blank_head"]),
        &mut cross,
    );
    collect_remote_head_cross(
        &request.expected_provisioned_head,
        &path(&["expected_provisioned_head"]),
        &mut cross,
    );
    if let Some(candidate) = choose(cross) {
        return Err(provision_cross_error(candidate));
    }
    Ok(request)
}

pub fn decode_provision_root_image_result(
    bytes: &[u8],
) -> Result<ProvisionRootImageResult, ProvisionRootImageWireDecodeError> {
    let result: ProvisionRootImageResult = decode_provision_payload(
        bytes,
        PROVISION_ROOT_IMAGE_RESULT_MAX_WIRE_BYTES,
        &PROVISION_ROOT_IMAGE_RESULT_SCHEMA,
    )?;
    let mut cross = Vec::new();
    collect_remote_head_cross(
        &result.resulting_head,
        &path(&["resulting_head"]),
        &mut cross,
    );
    if let Some(candidate) = choose(cross) {
        return Err(provision_cross_error(candidate));
    }
    Ok(result)
}

pub fn decode_provision_root_image_error(
    bytes: &[u8],
) -> Result<ProvisionRootImageError, ProvisionRootImageWireDecodeError> {
    decode_provision_payload(
        bytes,
        PROVISION_ROOT_IMAGE_ERROR_MAX_WIRE_BYTES,
        &PROVISION_ROOT_IMAGE_ERROR_SCHEMA,
    )
}

pub fn encode_provision_root_image_request(
    value: &ProvisionRootImageRequest,
) -> Result<Vec<u8>, ProvisionRootImageWireDecodeError> {
    encode_provision_payload(value, decode_provision_root_image_request)
}

pub fn encode_provision_root_image_result(
    value: &ProvisionRootImageResult,
) -> Result<Vec<u8>, ProvisionRootImageWireDecodeError> {
    encode_provision_payload(value, decode_provision_root_image_result)
}

pub fn encode_provision_root_image_error(
    value: &ProvisionRootImageError,
) -> Result<Vec<u8>, ProvisionRootImageWireDecodeError> {
    encode_provision_payload(value, decode_provision_root_image_error)
}

pub fn decode_node_identity(bytes: &[u8]) -> Result<NodeIdentity, ContractError> {
    decode(
        bytes,
        ContractName::NodeIdentity,
        NODE_IDENTITY_MAX_WIRE_BYTES,
        &NODE_IDENTITY_SCHEMA,
        |_| Ok(()),
    )
}

pub fn decode_node_placement_policy(bytes: &[u8]) -> Result<NodePlacementPolicy, ContractError> {
    decode(
        bytes,
        ContractName::NodePlacementPolicy,
        NODE_PLACEMENT_POLICY_MAX_WIRE_BYTES,
        &NODE_PLACEMENT_POLICY_SCHEMA,
        validate_node_placement_policy,
    )
}

pub fn decode_runtime_node_authority_apply(
    bytes: &[u8],
) -> Result<RuntimeNodeAuthorityApply, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeNodeAuthorityApply,
        RUNTIME_NODE_AUTHORITY_APPLY_MAX_WIRE_BYTES,
        &RUNTIME_NODE_AUTHORITY_APPLY_SCHEMA,
        validate_runtime_node_authority_apply,
    )
}

pub fn decode_runtime_node_authority_apply_result(
    bytes: &[u8],
) -> Result<RuntimeNodeAuthorityApplyResult, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeNodeAuthorityApplyResult,
        RUNTIME_NODE_AUTHORITY_APPLY_RESULT_MAX_WIRE_BYTES,
        &RUNTIME_NODE_AUTHORITY_APPLY_RESULT_SCHEMA,
        validate_runtime_node_authority_apply_result,
    )
}

pub fn decode_runtime_provisioner_trust_bundle(
    bytes: &[u8],
) -> Result<RuntimeProvisionerTrustBundle, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeProvisionerTrustBundle,
        RUNTIME_PROVISIONER_TRUST_BUNDLE_MAX_WIRE_BYTES,
        &RUNTIME_PROVISIONER_TRUST_BUNDLE_SCHEMA,
        validate_runtime_provisioner_trust_bundle,
    )
}

pub fn decode_runtime_provisioner_active_set(
    bytes: &[u8],
) -> Result<RuntimeProvisionerActiveSet, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeProvisionerActiveSet,
        RUNTIME_PROVISIONER_ACTIVE_SET_MAX_WIRE_BYTES,
        &RUNTIME_PROVISIONER_ACTIVE_SET_SCHEMA,
        validate_runtime_provisioner_active_set,
    )
}

pub fn decode_agent_registration_attempt(
    bytes: &[u8],
) -> Result<AgentRegistrationAttempt, ContractError> {
    decode(
        bytes,
        ContractName::AgentRegistrationAttempt,
        AGENT_REGISTRATION_ATTEMPT_MAX_WIRE_BYTES,
        &AGENT_REGISTRATION_ATTEMPT_SCHEMA,
        |_| Ok(()),
    )
}

pub fn decode_agent_session(bytes: &[u8]) -> Result<AgentSession, ContractError> {
    decode(
        bytes,
        ContractName::AgentSession,
        AGENT_SESSION_MAX_WIRE_BYTES,
        &AGENT_SESSION_SCHEMA,
        |_| Ok(()),
    )
}

pub fn decode_guest_runtime_profile_receipt(
    bytes: &[u8],
) -> Result<GuestRuntimeProfileReceipt, ContractError> {
    let contract = ContractName::GuestRuntimeProfileReceipt;
    let input = validate_payload(
        bytes,
        GUEST_RUNTIME_PROFILE_RECEIPT_MAX_WIRE_BYTES,
        &GUEST_RUNTIME_PROFILE_RECEIPT_SCHEMA,
        true,
    )
    .map_err(|error| contract_payload_error(contract, error))?;
    let decoded: GuestRuntimeProfileReceipt = serde_json::from_str(input)
        .map_err(|_| malformed_root(contract, MalformedProblem::InvalidValue))?;
    let value = serde_json::to_value(&decoded)
        .map_err(|_| malformed_root(contract, MalformedProblem::InvalidValue))?;
    if value_bytes(&value) != bytes {
        return Err(malformed_root(contract, MalformedProblem::InvalidValue));
    }
    Ok(decoded)
}

pub fn decode_admission_inventory_attestation(
    bytes: &[u8],
) -> Result<AdmissionInventoryAttestation, ContractError> {
    decode(
        bytes,
        ContractName::AdmissionInventoryAttestation,
        ADMISSION_INVENTORY_ATTESTATION_MAX_WIRE_BYTES,
        &ADMISSION_ATTESTATION_SCHEMA,
        |_| Ok(()),
    )
}

pub fn decode_desired_read_request(bytes: &[u8]) -> Result<DesiredReadRequest, ContractError> {
    decode(
        bytes,
        ContractName::DesiredReadRequest,
        DESIRED_READ_REQUEST_MAX_WIRE_BYTES,
        &DESIRED_READ_REQUEST_SCHEMA,
        |_| Ok(()),
    )
}

pub fn decode_desired_read_snapshot(bytes: &[u8]) -> Result<DesiredReadSnapshot, ContractError> {
    decode(
        bytes,
        ContractName::DesiredReadSnapshot,
        DESIRED_READ_SNAPSHOT_MAX_WIRE_BYTES,
        &DESIRED_READ_SNAPSHOT_SCHEMA,
        validate_desired_read_snapshot,
    )
}

pub fn decode_desired_runtime_spec(bytes: &[u8]) -> Result<DesiredRuntimeSpec, ContractError> {
    decode(
        bytes,
        ContractName::DesiredRuntimeSpec,
        DESIRED_RUNTIME_SPEC_MAX_WIRE_BYTES,
        &DESIRED_RUNTIME_SPEC_SCHEMA,
        |value| validate_desired_runtime_spec(value, true),
    )
}

pub fn decode_runtime_checkpoint(bytes: &[u8]) -> Result<RuntimeCheckpoint, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeCheckpoint,
        RUNTIME_CHECKPOINT_MAX_WIRE_BYTES,
        &RUNTIME_CHECKPOINT_SCHEMA,
        validate_runtime_checkpoint,
    )
}

pub fn decode_node_cleanup_checkpoint(
    bytes: &[u8],
) -> Result<NodeCleanupCheckpoint, ContractError> {
    decode(
        bytes,
        ContractName::NodeCleanupCheckpoint,
        NODE_CLEANUP_CHECKPOINT_MAX_WIRE_BYTES,
        &NODE_CLEANUP_CHECKPOINT_SCHEMA,
        validate_node_cleanup_checkpoint,
    )
}

pub fn decode_node_observation(bytes: &[u8]) -> Result<NodeObservation, ContractError> {
    decode(
        bytes,
        ContractName::NodeObservation,
        NODE_OBSERVATION_MAX_WIRE_BYTES,
        &NODE_OBSERVATION_SCHEMA,
        |value| validate_node_observation(value, true),
    )
}

pub fn decode_observation_acceptance(bytes: &[u8]) -> Result<ObservationAcceptance, ContractError> {
    decode(
        bytes,
        ContractName::ObservationAcceptance,
        OBSERVATION_ACCEPTANCE_MAX_WIRE_BYTES,
        &OBSERVATION_ACCEPTANCE_SCHEMA,
        validate_observation_acceptance,
    )
}

pub fn decode_runtime_spine_error(bytes: &[u8]) -> Result<RuntimeSpineError, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeSpineError,
        RUNTIME_SPINE_ERROR_MAX_WIRE_BYTES,
        &RUNTIME_SPINE_ERROR_SCHEMA,
        validate_runtime_spine_error,
    )
}

pub fn decode_runtime_volume_transition_evidence_request(
    bytes: &[u8],
) -> Result<RuntimeVolumeTransitionEvidenceRequest, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeVolumeTransitionEvidenceRequest,
        RUNTIME_VOLUME_TRANSITION_EVIDENCE_REQUEST_MAX_WIRE_BYTES,
        &RUNTIME_VOLUME_TRANSITION_EVIDENCE_REQUEST_SCHEMA,
        |_| Ok(()),
    )
}

pub fn decode_runtime_volume_transition_request(
    bytes: &[u8],
) -> Result<RuntimeVolumeTransitionRequest, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeVolumeTransitionRequest,
        RUNTIME_VOLUME_TRANSITION_REQUEST_MAX_WIRE_BYTES,
        &RUNTIME_VOLUME_TRANSITION_REQUEST_SCHEMA,
        validate_runtime_volume_transition_request,
    )
}

pub fn decode_runtime_volume_transition_success(
    bytes: &[u8],
) -> Result<RuntimeVolumeTransitionSuccess, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeVolumeTransitionSuccess,
        RUNTIME_VOLUME_TRANSITION_SUCCESS_MAX_WIRE_BYTES,
        &RUNTIME_VOLUME_TRANSITION_SUCCESS_SCHEMA,
        validate_runtime_volume_transition_success,
    )
}

pub fn decode_runtime_volume_transition_evidence_success(
    bytes: &[u8],
) -> Result<RuntimeVolumeTransitionEvidenceSuccess, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeVolumeTransitionEvidenceSuccess,
        RUNTIME_VOLUME_TRANSITION_EVIDENCE_SUCCESS_MAX_WIRE_BYTES,
        &RUNTIME_VOLUME_TRANSITION_EVIDENCE_SUCCESS_SCHEMA,
        validate_runtime_volume_transition_evidence_success,
    )
}

pub fn decode_runtime_volume_transition_error(
    bytes: &[u8],
) -> Result<RuntimeVolumeTransitionError, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeVolumeTransitionError,
        RUNTIME_VOLUME_TRANSITION_ERROR_MAX_WIRE_BYTES,
        &RUNTIME_VOLUME_TRANSITION_ERROR_SCHEMA,
        validate_runtime_volume_transition_error,
    )
}

pub fn decode_operation(bytes: &[u8]) -> Result<Operation, ContractError> {
    decode(
        bytes,
        ContractName::Operation,
        OPERATION_MAX_WIRE_BYTES,
        &OPERATION_SCHEMA,
        validate_operation,
    )
}

pub fn decode_contract_error(bytes: &[u8]) -> Result<ContractError, ContractError> {
    decode(
        bytes,
        ContractName::ContractError,
        CONTRACT_ERROR_MAX_WIRE_BYTES,
        &CONTRACT_ERROR_SCHEMA,
        validate_contract_error,
    )
}

pub fn encode_node_identity(value: &NodeIdentity) -> Result<Vec<u8>, ContractError> {
    encode(value, ContractName::NodeIdentity, decode_node_identity)
}

pub fn encode_node_placement_policy(value: &NodePlacementPolicy) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::NodePlacementPolicy,
        decode_node_placement_policy,
    )
}

pub fn encode_runtime_node_authority_apply(
    value: &RuntimeNodeAuthorityApply,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeNodeAuthorityApply,
        decode_runtime_node_authority_apply,
    )
}

pub fn encode_runtime_node_authority_apply_result(
    value: &RuntimeNodeAuthorityApplyResult,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeNodeAuthorityApplyResult,
        decode_runtime_node_authority_apply_result,
    )
}

pub fn encode_runtime_provisioner_trust_bundle(
    value: &RuntimeProvisionerTrustBundle,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeProvisionerTrustBundle,
        decode_runtime_provisioner_trust_bundle,
    )
}

pub fn encode_runtime_provisioner_active_set(
    value: &RuntimeProvisionerActiveSet,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeProvisionerActiveSet,
        decode_runtime_provisioner_active_set,
    )
}

pub fn encode_agent_registration_attempt(
    value: &AgentRegistrationAttempt,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::AgentRegistrationAttempt,
        decode_agent_registration_attempt,
    )
}

pub fn encode_agent_session(value: &AgentSession) -> Result<Vec<u8>, ContractError> {
    encode(value, ContractName::AgentSession, decode_agent_session)
}

pub fn encode_guest_runtime_profile_receipt(
    value: &GuestRuntimeProfileReceipt,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::GuestRuntimeProfileReceipt,
        decode_guest_runtime_profile_receipt,
    )
}

pub fn encode_admission_inventory_attestation(
    value: &AdmissionInventoryAttestation,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::AdmissionInventoryAttestation,
        decode_admission_inventory_attestation,
    )
}

pub fn encode_desired_read_request(value: &DesiredReadRequest) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::DesiredReadRequest,
        decode_desired_read_request,
    )
}

pub fn encode_desired_read_snapshot(value: &DesiredReadSnapshot) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::DesiredReadSnapshot,
        decode_desired_read_snapshot,
    )
}

pub fn encode_desired_runtime_spec(value: &DesiredRuntimeSpec) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::DesiredRuntimeSpec,
        decode_desired_runtime_spec,
    )
}

pub fn encode_runtime_checkpoint(value: &RuntimeCheckpoint) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeCheckpoint,
        decode_runtime_checkpoint,
    )
}

pub fn encode_node_cleanup_checkpoint(
    value: &NodeCleanupCheckpoint,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::NodeCleanupCheckpoint,
        decode_node_cleanup_checkpoint,
    )
}

pub fn encode_node_observation(value: &NodeObservation) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::NodeObservation,
        decode_node_observation,
    )
}

pub fn encode_observation_acceptance(
    value: &ObservationAcceptance,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::ObservationAcceptance,
        decode_observation_acceptance,
    )
}

pub fn encode_runtime_spine_error(value: &RuntimeSpineError) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeSpineError,
        decode_runtime_spine_error,
    )
}

pub fn encode_runtime_volume_transition_evidence_request(
    value: &RuntimeVolumeTransitionEvidenceRequest,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeVolumeTransitionEvidenceRequest,
        decode_runtime_volume_transition_evidence_request,
    )
}

pub fn encode_runtime_volume_transition_request(
    value: &RuntimeVolumeTransitionRequest,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeVolumeTransitionRequest,
        decode_runtime_volume_transition_request,
    )
}

pub fn encode_runtime_volume_transition_success(
    value: &RuntimeVolumeTransitionSuccess,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeVolumeTransitionSuccess,
        decode_runtime_volume_transition_success,
    )
}

pub fn encode_runtime_volume_transition_evidence_success(
    value: &RuntimeVolumeTransitionEvidenceSuccess,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeVolumeTransitionEvidenceSuccess,
        decode_runtime_volume_transition_evidence_success,
    )
}

pub fn encode_runtime_volume_transition_error(
    value: &RuntimeVolumeTransitionError,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeVolumeTransitionError,
        decode_runtime_volume_transition_error,
    )
}

pub fn encode_operation(value: &Operation) -> Result<Vec<u8>, ContractError> {
    encode(value, ContractName::Operation, decode_operation)
}

pub fn encode_contract_error(value: &ContractError) -> Result<Vec<u8>, ContractError> {
    encode(value, ContractName::ContractError, decode_contract_error)
}

fn validate_node_placement_policy(policy: &NodePlacementPolicy) -> Result<(), ContractError> {
    let mut candidates = Vec::new();
    if policy.version != ContractVersion::V1 {
        candidates.push(Candidate::at(
            &path(&["version"]),
            MalformedProblem::InvalidValue,
        ));
    }
    if policy.capabilities.guest_agent_protocol_version != ContractVersion::V1 {
        candidates.push(Candidate::at(
            &path(&["capabilities", "guest_agent_protocol_version"]),
            MalformedProblem::InvalidValue,
        ));
    }
    if policy.guest_ipv4_pool.prefix_length != 16
        || !private_aligned_ipv4_16(&policy.guest_ipv4_pool.network_address)
    {
        candidates.push(Candidate::at(
            &path(&["guest_ipv4_pool"]),
            MalformedProblem::InvalidValue,
        ));
    }
    if let Some(candidate) = choose(candidates) {
        return Err(malformed(ContractName::NodePlacementPolicy, candidate));
    }
    Ok(())
}

fn validate_runtime_node_authority_apply(
    apply: &RuntimeNodeAuthorityApply,
) -> Result<(), ContractError> {
    let contract = ContractName::RuntimeNodeAuthorityApply;
    let mutation_path = path(&["mutation"]);
    let mut candidates = Vec::new();
    match &apply.mutation {
        RuntimeNodeAuthorityMutation::Provision {
            node_identity,
            placement_policy,
        } => {
            if node_identity.version != ContractVersion::V1
                || node_identity.node_id != apply.node_id
                || node_identity.state != NodeIdentityState::Provisioned
            {
                candidates.push(Candidate::at(
                    &child(&mutation_path, "node_identity"),
                    MalformedProblem::InvalidValue,
                ));
            }
            collect_nested_policy_candidate(
                placement_policy,
                &child(&mutation_path, "placement_policy"),
                &mut candidates,
            );
            if placement_policy.node_id != apply.node_id
                || placement_policy.policy_revision.get() != 1
                || placement_policy.scheduling_state != RuntimeSchedulingState::Cordoned
            {
                candidates.push(Candidate::at(
                    &child(&mutation_path, "placement_policy"),
                    MalformedProblem::InvalidValue,
                ));
            }
        }
        RuntimeNodeAuthorityMutation::UpdatePolicy {
            expected_policy_revision,
            placement_policy,
        } => {
            collect_nested_policy_candidate(
                placement_policy,
                &child(&mutation_path, "placement_policy"),
                &mut candidates,
            );
            if placement_policy.node_id != apply.node_id
                || expected_policy_revision
                    .get()
                    .checked_add(1)
                    .is_none_or(|next| next != placement_policy.policy_revision.get())
            {
                candidates.push(Candidate::at(
                    &child(&mutation_path, "placement_policy"),
                    MalformedProblem::InvalidValue,
                ));
            }
        }
        RuntimeNodeAuthorityMutation::RotateCredential {
            expected_credential_id,
            expected_credential_binding,
            new_credential_id,
            new_credential_binding,
            ..
        } => {
            if expected_credential_id == new_credential_id
                || expected_credential_binding == new_credential_binding
            {
                candidates.push(Candidate::at(
                    &mutation_path,
                    MalformedProblem::InvalidValue,
                ));
            }
        }
        RuntimeNodeAuthorityMutation::Retire { .. } => {}
    }
    if let Some(candidate) = choose(candidates) {
        return Err(malformed(contract, candidate));
    }
    Ok(())
}

fn collect_nested_policy_candidate(
    policy: &NodePlacementPolicy,
    prefix: &[PathSegment],
    candidates: &mut Vec<Candidate>,
) {
    if let Err(error) = validate_node_placement_policy(policy) {
        candidates.push(rebase_contract_candidate(prefix, &error));
    }
}

fn validate_runtime_node_authority_apply_result(
    result: &RuntimeNodeAuthorityApplyResult,
) -> Result<(), ContractError> {
    let valid = match result.outcome {
        RuntimeNodeAuthorityOutcome::Provisioned => {
            result.identity_state == NodeIdentityState::Provisioned
                && result.policy_revision.get() == 1
        }
        RuntimeNodeAuthorityOutcome::PolicyUpdated
        | RuntimeNodeAuthorityOutcome::CredentialRotated => {
            result.identity_state == NodeIdentityState::Provisioned
        }
        RuntimeNodeAuthorityOutcome::Retired => result.identity_state == NodeIdentityState::Retired,
    };
    if !valid {
        return Err(malformed(
            ContractName::RuntimeNodeAuthorityApplyResult,
            Candidate::at(&[], MalformedProblem::InvalidValue),
        ));
    }
    Ok(())
}

fn validate_runtime_provisioner_trust_bundle(
    bundle: &RuntimeProvisionerTrustBundle,
) -> Result<(), ContractError> {
    let contract = ContractName::RuntimeProvisionerTrustBundle;
    let mut candidates = provisioner_credential_candidates(&bundle.credentials);
    let expected_valid = if bundle.trust_revision.get() == 1 {
        bundle.expected_previous.is_none()
    } else {
        bundle.expected_previous.as_ref().is_some_and(|previous| {
            previous
                .trust_revision
                .get()
                .checked_add(1)
                .is_some_and(|next| next == bundle.trust_revision.get())
        })
    };
    if !expected_valid {
        candidates.push(Candidate::at(
            &path(&["expected_previous"]),
            MalformedProblem::InvalidValue,
        ));
    }
    if let Some(candidate) = choose(candidates) {
        return Err(malformed(contract, candidate));
    }
    Ok(())
}

fn validate_runtime_provisioner_active_set(
    active_set: &RuntimeProvisionerActiveSet,
) -> Result<(), ContractError> {
    if let Some(candidate) = choose(provisioner_credential_candidates(&active_set.credentials)) {
        return Err(malformed(
            ContractName::RuntimeProvisionerActiveSet,
            candidate,
        ));
    }
    Ok(())
}

fn provisioner_credential_candidates(
    credentials: &[RuntimeProvisionerCredential],
) -> Vec<Candidate> {
    let credentials_path = path(&["credentials"]);
    let mut candidates = Vec::new();
    if credentials.is_empty() {
        candidates.push(Candidate::at(
            &credentials_path,
            MalformedProblem::InvalidValue,
        ));
        return candidates;
    }
    collect_unique_order(
        credentials,
        &credentials_path,
        |credential| credential.credential_id.as_str().as_bytes().to_vec(),
        &mut candidates,
    );
    if has_duplicate(
        credentials
            .iter()
            .map(|credential| credential.public_key_spki.as_str()),
    ) {
        candidates.push(Candidate::at(
            &credentials_path,
            MalformedProblem::DuplicateIdentity,
        ));
    }
    for (index, credential) in credentials.iter().enumerate() {
        if !canonical_ed25519_spki(&credential.public_key_spki) {
            candidates.push(Candidate::at(
                &child(&indexed(&credentials_path, index), "public_key_spki"),
                MalformedProblem::InvalidValue,
            ));
        }
    }
    candidates
}

fn canonical_ed25519_spki(value: &Base64UrlNoPad) -> bool {
    canonical_ed25519_spki_bytes(value).is_some()
}

pub(crate) fn canonical_ed25519_spki_bytes(value: &Base64UrlNoPad) -> Option<Vec<u8>> {
    const PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    URL_SAFE_NO_PAD
        .decode(value.as_str())
        .ok()
        .filter(|decoded| decoded.len() == PREFIX.len() + 32 && decoded.starts_with(&PREFIX))
}

fn private_aligned_ipv4_16(address: &Ipv4Address) -> bool {
    let address = ipv4_integer(address);
    if address & 0xffff != 0 {
        return false;
    }
    let first = address >> 24;
    let second = (address >> 16) & 0xff;
    first == 10 || (first == 172 && (16..=31).contains(&second)) || (first == 192 && second == 168)
}

pub(crate) fn validate_key_ring(loaded_kids: &[KeyId]) -> Result<(), ContractError> {
    if loaded_kids.len() > 64 {
        return Err(limit_error(
            ContractName::NodeObservation,
            &path(&["loaded_kids"]),
            LimitKind::ArrayItems,
            64,
        ));
    }
    validate_scalar_order(
        loaded_kids,
        ContractName::NodeObservation,
        &[PathSegment::Key("loaded_kids".to_owned())],
    )
}

fn authorization_id(record: &AuthorizationRecord) -> &Id {
    match &record.authorization {
        VolumeAuthorization::Takeover(authorization) => &authorization.authorization_id,
        VolumeAuthorization::DisposableRootDelete(authorization) => &authorization.authorization_id,
    }
}

fn authorization_volume_id(record: &AuthorizationRecord) -> &Id {
    match &record.authorization {
        VolumeAuthorization::Takeover(authorization) => &authorization.volume_id,
        VolumeAuthorization::DisposableRootDelete(authorization) => &authorization.volume_id,
    }
}

fn authorization_node_id(record: &AuthorizationRecord) -> &Id {
    match &record.authorization {
        VolumeAuthorization::Takeover(authorization) => &authorization.authorized_node_id,
        VolumeAuthorization::DisposableRootDelete(authorization) => {
            &authorization.authorized_node_id
        }
    }
}

fn valid_next_epoch(previous: FenceEpoch, next: FenceEpoch) -> bool {
    previous
        .get()
        .checked_add(1)
        .is_some_and(|value| value <= MAX_WIRE_INTEGER && value == next.get())
}

fn remote_head_valid(head: &RemoteHead) -> bool {
    if head.generation.get() == 0 {
        head.root_hash.is_none() && head.root_object_id.is_none()
    } else {
        head.root_hash.is_some() && head.root_object_id.is_some()
    }
}

fn remote_head_same_or_later(current: &RemoteHead, previous: &RemoteHead) -> bool {
    remote_head_valid(current)
        && remote_head_valid(previous)
        && (current.generation > previous.generation
            || (current.generation == previous.generation && current == previous))
}

fn authorization_record_valid(record: &AuthorizationRecord) -> bool {
    match (&record.authorization, &record.state) {
        (VolumeAuthorization::Takeover(authorization), AuthorizationState::Unconsumed) => {
            authorization.new_attachment_id != authorization.expected_attachment_id
        }
        (VolumeAuthorization::Takeover(authorization), AuthorizationState::Consumed(receipt)) => {
            match receipt.as_ref() {
                AuthorizationConsumedReceipt::Takeover(receipt) => {
                    authorization.new_attachment_id != authorization.expected_attachment_id
                        && receipt.authorization_id == authorization.authorization_id
                        && receipt.host_fence_event_id == authorization.host_fence_event_id
                        && receipt.volume_id == authorization.volume_id
                        && receipt.new_attachment_id == authorization.new_attachment_id
                        && valid_next_epoch(authorization.expected_epoch, receipt.resulting_epoch)
                        && remote_head_valid(&receipt.resulting_head)
                        && receipt.consumed_at <= authorization.not_after
                        && receipt
                            .consumed_at
                            .get()
                            .checked_add(authorization.lease_duration_ms)
                            .is_some_and(|value| value <= MAX_WIRE_INTEGER)
                }
                AuthorizationConsumedReceipt::BeginDisposableDelete(_) => false,
            }
        }
        (
            VolumeAuthorization::DisposableRootDelete(authorization),
            AuthorizationState::Unconsumed,
        ) => {
            remote_head_valid(&authorization.expected_head)
                && match &authorization.isolation_basis {
                    DisposableDeleteIsolationBasis::RuntimeStopped { node_id, .. } => {
                        node_id == &authorization.authorized_node_id
                    }
                    DisposableDeleteIsolationBasis::HostFenceEvent { .. } => true,
                }
        }
        (
            VolumeAuthorization::DisposableRootDelete(authorization),
            AuthorizationState::Consumed(receipt),
        ) => match receipt.as_ref() {
            AuthorizationConsumedReceipt::BeginDisposableDelete(receipt) => {
                remote_head_valid(&authorization.expected_head)
                    && match &authorization.isolation_basis {
                        DisposableDeleteIsolationBasis::RuntimeStopped { node_id, .. } => {
                            node_id == &authorization.authorized_node_id
                        }
                        DisposableDeleteIsolationBasis::HostFenceEvent { .. } => true,
                    }
                    && receipt.authorization_id == authorization.authorization_id
                    && receipt.volume_id == authorization.volume_id
                    && receipt.disk_id == authorization.disk_id
                    && receipt.cat_id == authorization.cat_id
                    && receipt.delete_id == authorization.delete_id
                    && receipt.prior_attachment_id == authorization.expected_attachment_id
                    && valid_next_epoch(authorization.expected_epoch, receipt.resulting_epoch)
                    && receipt.resulting_head == authorization.expected_head
                    && receipt.consumed_at <= authorization.not_after
            }
            AuthorizationConsumedReceipt::Takeover(_) => false,
        },
    }
}

fn volume_record_valid(record: &VolumeRecord) -> bool {
    if record.size_bytes == 0
        || record.size_bytes > MAX_WIRE_INTEGER
        || !remote_head_valid(&record.head)
    {
        return false;
    }
    match (
        &record.admin_state,
        &record.lease_owner,
        &record.lease_expires_at,
    ) {
        (VolumeAdminState::Active, None, None) => {}
        (VolumeAdminState::Active, Some(_), Some(expires_at))
            if record.lease_epoch.get() > 0 && expires_at.get() > 0 => {}
        (VolumeAdminState::Deleting { .. }, None, None) if record.lease_epoch.get() > 0 => {}
        _ => return false,
    }
    let Some(last) = &record.last_transition else {
        return matches!(record.admin_state, VolumeAdminState::Active)
            && record.lease_owner.is_none();
    };
    match last {
        LastVolumeTransition::NormalAcquire { request, result } => {
            request.volume_id == record.volume_id
                && result.volume_id == request.volume_id
                && result.transition_id == request.transition_id
                && result.attachment_id == request.attachment_id
                && valid_next_epoch(request.expected_unowned_epoch, result.resulting_epoch)
                && result.lease_expires_at.get() >= request.lease_duration_ms
                && matches!(record.admin_state, VolumeAdminState::Active)
                && record.lease_owner.as_ref() == Some(&result.attachment_id)
                && record.lease_epoch == result.resulting_epoch
                && remote_head_same_or_later(&record.head, &result.resulting_head)
        }
        LastVolumeTransition::Release { request, result } => {
            request.volume_id == record.volume_id
                && result.volume_id == request.volume_id
                && result.transition_id == request.transition_id
                && result.released_attachment_id == request.attachment_id
                && valid_next_epoch(request.expected_epoch, result.resulting_epoch)
                && matches!(record.admin_state, VolumeAdminState::Active)
                && record.lease_owner.is_none()
                && record.lease_epoch == result.resulting_epoch
                && record.head == result.resulting_head
                && remote_head_valid(&result.resulting_head)
        }
        LastVolumeTransition::Takeover { .. } => {
            matches!(record.admin_state, VolumeAdminState::Active) && record.lease_owner.is_some()
        }
        LastVolumeTransition::BeginDelete { request, result } => {
            request.volume_id == record.volume_id
                && result.delete_id == request.delete_id
                && result.disk_id == request.disk_id
                && result.volume_id == request.volume_id
                && valid_next_epoch(request.expected_unowned_epoch, result.resulting_epoch)
                && result.resulting_head == request.expected_head
                && record.lease_epoch == result.resulting_epoch
                && record.head == result.resulting_head
                && matches!(
                    &record.admin_state,
                    VolumeAdminState::Deleting { delete_id } if delete_id == &result.delete_id
                )
        }
        LastVolumeTransition::BeginDisposableDelete { .. } => {
            matches!(record.admin_state, VolumeAdminState::Deleting { .. })
        }
    }
}

fn delete_completion_valid(receipt: &DeleteCompletionReceipt) -> bool {
    match receipt {
        DeleteCompletionReceipt::Normal {
            request,
            deleting_epoch,
            deleting_head,
            ..
        } => {
            remote_head_valid(&request.expected_head)
                && request.expected_head == *deleting_head
                && valid_next_epoch(request.expected_unowned_epoch, *deleting_epoch)
        }
        DeleteCompletionReceipt::DisposableRoot { deleting_head, .. } => {
            remote_head_valid(deleting_head)
        }
    }
}

/// Returns whether the four stored rows form the one closed authorization
/// evidence bundle allowed by the runtime-volume-transition contract.
///
/// This is the shared, context-free closure used by both the public success
/// codec and the Volume Authority adapter. The caller still owns transport
/// context such as binding the primary authorization to the authenticated
/// session's Node.
pub fn volume_transition_evidence_bundle_is_closed(
    primary: &AuthorizationRecord,
    current_volume: Option<&VolumeRecord>,
    delete_completion: Option<&DeleteCompletionReceipt>,
    direct_successor: Option<&AuthorizationRecord>,
) -> bool {
    if !authorization_record_valid(primary)
        || current_volume.is_some_and(|record| !volume_record_valid(record))
        || delete_completion.is_some_and(|receipt| !delete_completion_valid(receipt))
        || direct_successor.is_some_and(|record| !authorization_record_valid(record))
        || (current_volume.is_some() && delete_completion.is_some())
    {
        return false;
    }

    let primary_id = authorization_id(primary);
    let volume_id = authorization_volume_id(primary);
    if current_volume.is_some_and(|record| &record.volume_id != volume_id)
        || delete_completion.is_some_and(|receipt| completion_volume_id(receipt) != volume_id)
    {
        return false;
    }
    if let VolumeAuthorization::DisposableRootDelete(authorization) = &primary.authorization {
        if delete_completion
            .is_some_and(|completion| completion_delete_id(completion) != &authorization.delete_id)
        {
            return false;
        }
    }

    let marker = current_volume
        .and_then(volume_authorization_marker)
        .or_else(|| delete_completion.and_then(completion_authorization_marker));
    match marker.filter(|marker| *marker != primary_id) {
        None if direct_successor.is_none() => {}
        Some(marker)
            if direct_successor.is_some_and(|record| authorization_id(record) == marker) => {}
        _ => return false,
    }

    if let Some(record) = direct_successor {
        if authorization_id(record) == primary_id
            || authorization_volume_id(record) != volume_id
            || !direct_successor_postcondition_is_closed(record, current_volume, delete_completion)
            || !direct_successor_is_monotonic(primary, record)
        {
            return false;
        }
    } else if marker == Some(primary_id)
        && !direct_successor_postcondition_is_closed(primary, current_volume, delete_completion)
    {
        return false;
    }

    primary_postcondition_is_monotonic(primary, current_volume, delete_completion)
}

fn completion_volume_id(receipt: &DeleteCompletionReceipt) -> &Id {
    match receipt {
        DeleteCompletionReceipt::Normal { request, .. } => &request.volume_id,
        DeleteCompletionReceipt::DisposableRoot { volume_id, .. } => volume_id,
    }
}

fn completion_delete_id(receipt: &DeleteCompletionReceipt) -> &Id {
    match receipt {
        DeleteCompletionReceipt::Normal { request, .. } => &request.delete_id,
        DeleteCompletionReceipt::DisposableRoot { delete_id, .. } => delete_id,
    }
}

fn volume_authorization_marker(record: &VolumeRecord) -> Option<&Id> {
    match &record.last_transition {
        Some(LastVolumeTransition::Takeover { authorization_id })
        | Some(LastVolumeTransition::BeginDisposableDelete { authorization_id }) => {
            Some(authorization_id)
        }
        _ => None,
    }
}

fn completion_authorization_marker(receipt: &DeleteCompletionReceipt) -> Option<&Id> {
    match receipt {
        DeleteCompletionReceipt::Normal { .. } => None,
        DeleteCompletionReceipt::DisposableRoot {
            authorization_id, ..
        } => Some(authorization_id),
    }
}

fn direct_successor_postcondition_is_closed(
    record: &AuthorizationRecord,
    current_volume: Option<&VolumeRecord>,
    delete_completion: Option<&DeleteCompletionReceipt>,
) -> bool {
    let AuthorizationState::Consumed(receipt) = &record.state else {
        return false;
    };
    match (&record.authorization, receipt.as_ref()) {
        (
            VolumeAuthorization::Takeover(authorization),
            AuthorizationConsumedReceipt::Takeover(receipt),
        ) => {
            let Some(current) = current_volume else {
                return false;
            };
            matches!(
                &current.last_transition,
                Some(LastVolumeTransition::Takeover { authorization_id })
                    if authorization_id == &authorization.authorization_id
            ) && matches!(current.admin_state, VolumeAdminState::Active)
                && current.lease_owner.as_ref() == Some(&receipt.new_attachment_id)
                && current.lease_epoch == receipt.resulting_epoch
                && remote_head_same_or_later(&current.head, &receipt.resulting_head)
        }
        (
            VolumeAuthorization::DisposableRootDelete(authorization),
            AuthorizationConsumedReceipt::BeginDisposableDelete(receipt),
        ) => match (current_volume, delete_completion) {
            (Some(current), None) => {
                disposable_direct_postcondition_is_closed(current, authorization, receipt)
            }
            (None, Some(completion)) => {
                disposable_completion_is_closed(completion, authorization, receipt)
            }
            _ => false,
        },
        _ => false,
    }
}

fn disposable_direct_postcondition_is_closed(
    record: &VolumeRecord,
    authorization: &DisposableRootDeleteAuthorization,
    receipt: &BeginDisposableDeleteConsumedReceipt,
) -> bool {
    matches!(
        &record.admin_state,
        VolumeAdminState::Deleting { delete_id } if delete_id == &authorization.delete_id
    ) && record.lease_owner.is_none()
        && record.lease_expires_at.is_none()
        && record.lease_epoch == receipt.resulting_epoch
        && record.head == receipt.resulting_head
        && matches!(
            &record.last_transition,
            Some(LastVolumeTransition::BeginDisposableDelete { authorization_id })
                if authorization_id == &authorization.authorization_id
        )
}

fn disposable_completion_is_closed(
    completion: &DeleteCompletionReceipt,
    authorization: &DisposableRootDeleteAuthorization,
    receipt: &BeginDisposableDeleteConsumedReceipt,
) -> bool {
    matches!(
        completion,
        DeleteCompletionReceipt::DisposableRoot {
            disk_id,
            volume_id,
            delete_id,
            authorization_id,
            prior_attachment_id,
            deleting_epoch,
            deleting_head,
            completed_at,
            ..
        } if disk_id == &authorization.disk_id
            && volume_id == &authorization.volume_id
            && delete_id == &authorization.delete_id
            && authorization_id == &authorization.authorization_id
            && prior_attachment_id == &authorization.expected_attachment_id
            && deleting_epoch == &receipt.resulting_epoch
            && deleting_head == &receipt.resulting_head
            && completed_at >= &receipt.consumed_at
    )
}

fn direct_successor_is_monotonic(
    primary: &AuthorizationRecord,
    direct: &AuthorizationRecord,
) -> bool {
    let (VolumeAuthorization::Takeover(_), AuthorizationState::Consumed(primary_receipt)) =
        (&primary.authorization, &primary.state)
    else {
        return true;
    };
    let AuthorizationConsumedReceipt::Takeover(primary_receipt) = primary_receipt.as_ref() else {
        return false;
    };
    match (&direct.authorization, &direct.state) {
        (VolumeAuthorization::Takeover(authorization), AuthorizationState::Consumed(receipt)) => {
            let AuthorizationConsumedReceipt::Takeover(receipt) = receipt.as_ref() else {
                return false;
            };
            ((authorization.expected_attachment_id == primary_receipt.new_attachment_id
                && authorization.expected_epoch == primary_receipt.resulting_epoch)
                // A signed direct authorization may describe the current tip
                // after one or more intervening ownership cycles. A strictly
                // higher predecessor epoch is itself a closed fence over the
                // primary receipt; equal epoch with another owner remains a
                // competing branch.
                || authorization.expected_epoch > primary_receipt.resulting_epoch)
                && remote_head_same_or_later(
                    &receipt.resulting_head,
                    &primary_receipt.resulting_head,
                )
        }
        (
            VolumeAuthorization::DisposableRootDelete(authorization),
            AuthorizationState::Consumed(_),
        ) => {
            ((authorization.expected_attachment_id == primary_receipt.new_attachment_id
                && authorization.expected_epoch == primary_receipt.resulting_epoch)
                || authorization.expected_epoch > primary_receipt.resulting_epoch)
                && remote_head_same_or_later(
                    &authorization.expected_head,
                    &primary_receipt.resulting_head,
                )
        }
        _ => false,
    }
}

fn primary_postcondition_is_monotonic(
    primary: &AuthorizationRecord,
    current_volume: Option<&VolumeRecord>,
    delete_completion: Option<&DeleteCompletionReceipt>,
) -> bool {
    let AuthorizationState::Consumed(receipt) = &primary.state else {
        return true;
    };
    match (&primary.authorization, receipt.as_ref()) {
        (VolumeAuthorization::Takeover(_), AuthorizationConsumedReceipt::Takeover(receipt)) => {
            let (epoch, head) = match (current_volume, delete_completion) {
                (Some(current), None) => (current.lease_epoch, &current.head),
                (
                    None,
                    Some(DeleteCompletionReceipt::Normal {
                        deleting_epoch,
                        deleting_head,
                        ..
                    }),
                )
                | (
                    None,
                    Some(DeleteCompletionReceipt::DisposableRoot {
                        deleting_epoch,
                        deleting_head,
                        ..
                    }),
                ) => (*deleting_epoch, deleting_head),
                (None, None) => return true,
                _ => return false,
            };
            epoch >= receipt.resulting_epoch
                && remote_head_same_or_later(head, &receipt.resulting_head)
        }
        (
            VolumeAuthorization::DisposableRootDelete(authorization),
            AuthorizationConsumedReceipt::BeginDisposableDelete(receipt),
        ) => match (current_volume, delete_completion) {
            (Some(current), None) => {
                disposable_direct_postcondition_is_closed(current, authorization, receipt)
            }
            (None, Some(completion)) => {
                disposable_completion_is_closed(completion, authorization, receipt)
            }
            // A sweeper crash between row deletion and completion insertion is
            // incomplete recovery evidence, not permission to infer success.
            (None, None) => true,
            _ => false,
        },
        _ => false,
    }
}

fn validate_runtime_volume_transition_evidence_success(
    success: &RuntimeVolumeTransitionEvidenceSuccess,
) -> Result<(), ContractError> {
    let contract = ContractName::RuntimeVolumeTransitionEvidenceSuccess;
    let mut candidates = Vec::new();
    if authorization_id(&success.authorization) != &success.authorization_id
        || authorization_node_id(&success.authorization) != &success.session.node_id
        || !authorization_record_valid(&success.authorization)
    {
        candidates.push(Candidate::at(
            &path(&["authorization"]),
            MalformedProblem::InvalidValue,
        ));
    }
    if success
        .current_volume
        .as_ref()
        .is_some_and(|record| !volume_record_valid(record))
    {
        candidates.push(Candidate::at(
            &path(&["current_volume"]),
            MalformedProblem::InvalidValue,
        ));
    }
    if success
        .delete_completion
        .as_ref()
        .is_some_and(|receipt| !delete_completion_valid(receipt))
    {
        candidates.push(Candidate::at(
            &path(&["delete_completion"]),
            MalformedProblem::InvalidValue,
        ));
    }
    if success
        .direct_successor_authorization
        .as_ref()
        .is_some_and(|record| !authorization_record_valid(record))
    {
        candidates.push(Candidate::at(
            &path(&["direct_successor_authorization"]),
            MalformedProblem::InvalidValue,
        ));
    }

    if !volume_transition_evidence_bundle_is_closed(
        &success.authorization,
        success.current_volume.as_ref(),
        success.delete_completion.as_ref(),
        success.direct_successor_authorization.as_ref(),
    ) {
        let path = if success.direct_successor_authorization.is_some() {
            path(&["direct_successor_authorization"])
        } else {
            Vec::new()
        };
        candidates.push(Candidate::at(&path, MalformedProblem::InvalidValue));
    }

    if let Some(candidate) = choose(candidates) {
        return Err(malformed(contract, candidate));
    }
    Ok(())
}

fn validate_runtime_volume_transition_request(
    request: &RuntimeVolumeTransitionRequest,
) -> Result<(), ContractError> {
    let contract = ContractName::RuntimeVolumeTransitionRequest;
    let mut candidates = Vec::new();
    if request.session.node_id != request.placement.node_id {
        candidates.push(Candidate::at(
            &path(&["session", "node_id"]),
            MalformedProblem::InvalidValue,
        ));
    }
    match &request.transition {
        RuntimeVolumeTransition::Acquire {
            request:
                VolumeAcquireRequest::Normal {
                    desired_revision,
                    placement_epoch,
                    ..
                },
        } => {
            if *desired_revision != request.desired_revision {
                candidates.push(Candidate::at(
                    &path(&["transition", "request", "desired_revision"]),
                    MalformedProblem::InvalidValue,
                ));
            }
            if *placement_epoch != request.placement.placement_epoch {
                candidates.push(Candidate::at(
                    &path(&["transition", "request", "placement_epoch"]),
                    MalformedProblem::InvalidValue,
                ));
            }
        }
        RuntimeVolumeTransition::Release { cleanup } => {
            if cleanup.inventory_session != request.session {
                candidates.push(Candidate::at(
                    &path(&["transition", "cleanup", "inventory_session"]),
                    MalformedProblem::InvalidValue,
                ));
            }
            if !matches!(cleanup.target, CleanupTarget::Volume { .. })
                || cleanup.volume_release.is_none()
                || cleanup.desired_read_position < cleanup.inventory_read_position
            {
                candidates.push(Candidate::at(
                    &path(&["transition", "cleanup"]),
                    MalformedProblem::InvalidValue,
                ));
            }
        }
        RuntimeVolumeTransition::Acquire {
            request: VolumeAcquireRequest::Takeover { .. },
        }
        | RuntimeVolumeTransition::DeleteDisposableRoot { .. } => {}
        RuntimeVolumeTransition::CommitInitialized {
            filesystem,
            new_remote_head,
        } => {
            let transition_path = path(&["transition"]);
            collect_persistent_filesystem_binding_cross(
                filesystem,
                &transition_path,
                true,
                &mut candidates,
            );
            collect_remote_head_cross(
                new_remote_head,
                &child(&transition_path, "new_remote_head"),
                &mut candidates,
            );
            if new_remote_head.generation.get() == 0 {
                candidates.push(Candidate::field(
                    &transition_path,
                    "new_remote_head",
                    MalformedProblem::InvalidValue,
                ));
            }
        }
    }
    if let Some(candidate) = choose(candidates) {
        return Err(malformed(contract, candidate));
    }
    Ok(())
}

fn validate_runtime_volume_transition_success(
    success: &RuntimeVolumeTransitionSuccess,
) -> Result<(), ContractError> {
    let contract = ContractName::RuntimeVolumeTransitionSuccess;
    let mut candidates = Vec::new();
    if success.session.node_id != success.placement.node_id {
        candidates.push(Candidate::at(
            &path(&["session", "node_id"]),
            MalformedProblem::InvalidValue,
        ));
    }
    let (head, head_path) = match &success.outcome {
        RuntimeVolumeTransitionOutcome::LeaseGranted { grant } => {
            (&grant.head, path(&["outcome", "grant", "head"]))
        }
        RuntimeVolumeTransitionOutcome::Released { release } => (
            &release.resulting_head,
            path(&["outcome", "release", "resulting_head"]),
        ),
        RuntimeVolumeTransitionOutcome::DisposableRootDeleting { receipt } => (
            &receipt.resulting_head,
            path(&["outcome", "receipt", "resulting_head"]),
        ),
        RuntimeVolumeTransitionOutcome::PersistentInitialized { receipt } => {
            let receipt_path = path(&["outcome", "receipt"]);
            collect_remote_head_cross(
                &receipt.expected_blank_head,
                &child(&receipt_path, "expected_blank_head"),
                &mut candidates,
            );
            if receipt.expected_blank_head.generation.get() != 0
                || receipt.initialized_head.generation.get() == 0
                || receipt.initialization_token == receipt.filesystem_uuid
            {
                candidates.push(Candidate::at(&receipt_path, MalformedProblem::InvalidValue));
            }
            (
                &receipt.initialized_head,
                child(&receipt_path, "initialized_head"),
            )
        }
    };
    collect_remote_head_cross(head, &head_path, &mut candidates);
    if let Some(candidate) = choose(candidates) {
        return Err(malformed(contract, candidate));
    }
    Ok(())
}

fn validate_desired_read_snapshot(snapshot: &DesiredReadSnapshot) -> Result<(), ContractError> {
    let contract = ContractName::DesiredReadSnapshot;
    let specs_path = path(&["desired_specs"]);
    let mut candidates = Vec::new();
    collect_unique_order(
        &snapshot.desired_specs,
        &specs_path,
        |spec| spec.cat_id.as_str().as_bytes().to_vec(),
        &mut candidates,
    );
    let all_volumes = snapshot
        .desired_specs
        .iter()
        .flat_map(|spec| spec.volumes.iter())
        .collect::<Vec<_>>();
    if has_duplicate(all_volumes.iter().map(|volume| &volume.volume_intent_id))
        || has_duplicate(all_volumes.iter().map(|volume| &volume.disk_id))
        || has_duplicate(all_volumes.iter().map(|volume| &volume.volume_id))
        || has_duplicate(all_volumes.iter().map(|volume| &volume.attachment_id))
        || has_duplicate(
            all_volumes
                .iter()
                .filter_map(|volume| volume.mount.as_ref().map(|mount| &mount.filesystem_uuid)),
        )
        || has_duplicate(all_volumes.iter().filter_map(|volume| {
            let FilesystemInitialization::Initialize {
                initialization_token,
                ..
            } = &volume.mount.as_ref()?.initialization
            else {
                return None;
            };
            Some(initialization_token)
        }))
    {
        candidates.push(Candidate::at(
            &specs_path,
            MalformedProblem::DuplicateIdentity,
        ));
    }
    for (index, spec) in snapshot.desired_specs.iter().enumerate() {
        if let Err(error) = validate_desired_runtime_spec(spec, true) {
            candidates.push(rebase_contract_candidate(
                &indexed(&specs_path, index),
                &error,
            ));
        }
    }
    if snapshot.issued_at_unix_ms.get() >= snapshot.expires_at_unix_ms.get() {
        candidates.push(Candidate::at(&[], MalformedProblem::InvalidValue));
    }
    if let Some(candidate) = choose(candidates) {
        return Err(malformed(contract, candidate));
    }
    Ok(())
}

fn validate_observation_acceptance(
    acceptance: &ObservationAcceptance,
) -> Result<(), ContractError> {
    let contract = ContractName::ObservationAcceptance;
    let mut candidates = Vec::new();
    if acceptance.accepted_at_unix_ms.get() >= acceptance.lease_deadline_unix_ms.get() {
        candidates.push(Candidate::at(&[], MalformedProblem::InvalidValue));
    }
    if let ObservationInventoryAcceptance::Full { attestation } = &acceptance.inventory {
        if attestation.node_id != acceptance.session.node_id
            || attestation.agent_session_epoch != acceptance.session.agent_session_epoch
            || attestation.accepted_at_unix_ms != acceptance.accepted_at_unix_ms
        {
            candidates.push(Candidate::at(
                &path(&["inventory"]),
                MalformedProblem::InvalidValue,
            ));
        }
    }
    if let Some(candidate) = choose(candidates) {
        return Err(malformed(contract, candidate));
    }
    Ok(())
}

fn validate_runtime_spine_error(error: &RuntimeSpineError) -> Result<(), ContractError> {
    if let RuntimeSpineErrorDetail::ContractError { contract_error } = error.error.as_ref() {
        validate_contract_error(contract_error).map_err(|nested| {
            malformed(
                ContractName::RuntimeSpineError,
                rebase_contract_candidate(&path(&["error", "contract_error"]), &nested),
            )
        })?;
    }
    Ok(())
}

fn validate_runtime_volume_transition_error(
    error: &RuntimeVolumeTransitionError,
) -> Result<(), ContractError> {
    if let RuntimeVolumeTransitionErrorDetail::ContractError { contract_error } =
        error.error.as_ref()
    {
        validate_contract_error(contract_error).map_err(|nested| {
            malformed(
                ContractName::RuntimeVolumeTransitionError,
                rebase_contract_candidate(&path(&["error", "contract_error"]), &nested),
            )
        })?;
    }
    Ok(())
}

fn rebase_contract_candidate(prefix: &[PathSegment], error: &ContractError) -> Candidate {
    let (pointer, problem) = match error.error.as_ref() {
        ContractErrorDetail::MalformedPayload {
            json_pointer,
            problem,
            ..
        } => (json_pointer.as_str(), *problem),
        _ => return Candidate::at(prefix, MalformedProblem::InvalidValue),
    };
    let Some(suffix) = parse_rendered_pointer(pointer) else {
        return Candidate::at(prefix, MalformedProblem::InvalidValue);
    };
    let mut path = prefix.to_vec();
    path.extend(suffix);
    Candidate::at(&path, problem)
}

fn parse_rendered_pointer(pointer: &str) -> Option<Vec<PathSegment>> {
    if pointer.is_empty() {
        return Some(Vec::new());
    }
    if !pointer.starts_with('/') {
        return None;
    }
    pointer[1..]
        .split('/')
        .map(|component| {
            let mut decoded = String::new();
            let mut characters = component.chars();
            while let Some(character) = characters.next() {
                if character != '~' {
                    decoded.push(character);
                    continue;
                }
                match characters.next()? {
                    '0' => decoded.push('~'),
                    '1' => decoded.push('/'),
                    _ => return None,
                }
            }
            if !decoded.is_empty() && decoded.bytes().all(|byte| byte.is_ascii_digit()) {
                decoded.parse::<usize>().ok().map(PathSegment::Index)
            } else {
                Some(PathSegment::Key(decoded))
            }
        })
        .collect()
}

fn validate_desired_runtime_spec(
    spec: &DesiredRuntimeSpec,
    compare_digest: bool,
) -> Result<(), ContractError> {
    let contract = ContractName::DesiredRuntimeSpec;
    let volumes_path = path(&["volumes"]);
    let endpoints_path = path(&["endpoints"]);
    let mut arrays = Vec::new();
    collect_unique_order(
        &spec.volumes,
        &volumes_path,
        |volume| volume.volume_intent_id.as_str().as_bytes().to_vec(),
        &mut arrays,
    );
    let secondary_identity_duplicate =
        has_duplicate(spec.volumes.iter().map(|volume| &volume.disk_id))
            || has_duplicate(spec.volumes.iter().map(|volume| &volume.volume_id))
            || has_duplicate(spec.volumes.iter().map(|volume| &volume.attachment_id))
            || has_duplicate(
                spec.volumes
                    .iter()
                    .map(|volume| &volume.guest_device.serial),
            );
    if secondary_identity_duplicate {
        arrays.push(Candidate::at(
            &volumes_path,
            MalformedProblem::DuplicateIdentity,
        ));
    }
    if has_duplicate(spec.volumes.iter().map(|volume| match &volume.acquire {
        VolumeAcquire::Normal { transition_id, .. } => transition_id.as_str(),
        VolumeAcquire::Takeover { authorization_id } => authorization_id.as_str(),
    })) {
        // Acquire identifiers are variant-tagged at every lineage boundary,
        // but one Desired set may not reuse the same text across variants.
        // Rejecting it here prevents logs/checkpoints/operators from ever
        // having two simultaneously current meanings for one identifier.
        arrays.push(Candidate::at(
            &volumes_path,
            MalformedProblem::DuplicateIdentity,
        ));
    }
    if has_duplicate(spec.volumes.iter().map(|volume| volume.guest_device.slot)) {
        arrays.push(Candidate::at(
            &volumes_path,
            MalformedProblem::DuplicateIdentity,
        ));
    }
    if has_duplicate(
        spec.volumes
            .iter()
            .filter_map(|volume| volume.mount.as_ref().map(|mount| &mount.filesystem_uuid)),
    ) || has_duplicate(
        spec.volumes
            .iter()
            .filter_map(|volume| volume.mount.as_ref().map(|mount| &mount.mount_path)),
    ) || has_duplicate(spec.volumes.iter().filter_map(|volume| {
        let FilesystemInitialization::Initialize {
            initialization_token,
            ..
        } = &volume.mount.as_ref()?.initialization
        else {
            return None;
        };
        Some(initialization_token)
    })) {
        arrays.push(Candidate::at(
            &volumes_path,
            MalformedProblem::DuplicateIdentity,
        ));
    }
    collect_unique_order(
        &spec.endpoints,
        &endpoints_path,
        |endpoint| endpoint.endpoint_id.as_str().as_bytes().to_vec(),
        &mut arrays,
    );
    if has_duplicate(
        spec.endpoints
            .iter()
            .map(|endpoint| endpoint.hostname.as_str()),
    ) {
        arrays.push(Candidate::at(
            &endpoints_path,
            MalformedProblem::DuplicateIdentity,
        ));
    }
    if let Some(candidate) = choose(arrays) {
        return Err(malformed(contract, candidate));
    }

    let mut cross = Vec::new();
    collect_network_config_cross(
        &spec.runtime.network_config,
        &path(&["runtime", "network_config"]),
        &mut cross,
    );
    for (index, volume) in spec.volumes.iter().enumerate() {
        let volume_path = indexed(&volumes_path, index);
        if usize::from(volume.guest_device.slot) != index
            || match index {
                0 => volume.disk_kind != DiskKind::Root,
                _ => volume.disk_kind != DiskKind::Persistent,
            }
        {
            cross.push(Candidate::at(&volume_path, MalformedProblem::InvalidValue));
        }
        let disposition_valid = match spec.target {
            RuntimeTarget::Deleted => !matches!(volume.disposition, VolumeDisposition::Retain),
            _ => matches!(volume.disposition, VolumeDisposition::Retain),
        };
        if !disposition_valid {
            cross.push(Candidate::at(&[], MalformedProblem::InvalidValue));
        }
        if matches!(
            volume.disposition,
            VolumeDisposition::DeleteDisposableRoot { .. }
        ) && volume.disk_kind != DiskKind::Root
        {
            cross.push(Candidate::at(&volume_path, MalformedProblem::InvalidValue));
        }
        let mount_valid = match volume.disk_kind {
            DiskKind::Root => volume.mount.is_none(),
            DiskKind::Persistent => volume.mount.is_some(),
        };
        if !mount_valid {
            cross.push(Candidate::at(&volume_path, MalformedProblem::InvalidValue));
        }
        if volume
            .mount
            .as_ref()
            .is_some_and(|mount| mount.mount_path.as_str() == "/")
        {
            cross.push(Candidate::field(
                &volume_path,
                "mount",
                MalformedProblem::InvalidValue,
            ));
        }
        if let Some(Ext4MountIntent {
            filesystem_uuid,
            initialization:
                FilesystemInitialization::Initialize {
                    initialization_token,
                    expected_blank_head,
                },
            ..
        }) = &volume.mount
        {
            collect_remote_head_cross(
                expected_blank_head,
                &child(
                    &child(&child(&volume_path, "mount"), "initialization"),
                    "expected_blank_head",
                ),
                &mut cross,
            );
            if expected_blank_head.generation.get() != 0 || initialization_token == filesystem_uuid
            {
                cross.push(Candidate::at(
                    &child(
                        &child(&child(&volume_path, "mount"), "initialization"),
                        "expected_blank_head",
                    ),
                    MalformedProblem::InvalidValue,
                ));
            }
        }
    }
    // DesiredRuntimeSpec remains usable by the non-storage lifecycle and gate
    // contracts before a Root volume has been assigned.  The production
    // storage reconciliation prefix independently requires one canonical Root
    // followed by zero or more Persistent volumes before it can mutate host
    // state; imposing that stronger precondition on this shared wire type
    // would invalidate otherwise closed endpoint-only Desired snapshots.
    if spec.volumes.len() > 64 {
        cross.push(Candidate::at(&volumes_path, MalformedProblem::InvalidValue));
    }
    if let RuntimeTransition::RequireIdle {
        source_revision, ..
    } = spec.transition
    {
        if spec.target != RuntimeTarget::Suspended
            || source_revision.get() >= spec.desired_revision.get()
        {
            cross.push(Candidate::at(&[], MalformedProblem::InvalidValue));
        }
    }
    if let Some(candidate) = choose(cross) {
        return Err(malformed(contract, candidate));
    }
    if compare_digest && unchecked_spec_digest(spec) != spec.spec_digest {
        return Err(malformed(
            contract,
            Candidate::field(&[], "spec_digest", MalformedProblem::InvalidValue),
        ));
    }
    Ok(())
}

fn collect_network_config_cross(
    network: &NetworkConfig,
    network_path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    let guest = ipv4_integer(&network.guest_ipv4);
    let gateway = ipv4_integer(&network.gateway_ipv4);
    let same_subnet = guest & !3 == gateway & !3;
    let guest_host = guest & 3;
    let gateway_host = gateway & 3;
    if !same_subnet
        || guest == gateway
        || matches!(guest_host, 0 | 3)
        || matches!(gateway_host, 0 | 3)
    {
        output.push(Candidate::at(network_path, MalformedProblem::InvalidValue));
    }
    let first_mac_octet = u8::from_str_radix(&network.guest_mac.as_str()[..2], 16)
        .expect("validated MacAddress has a first octet");
    if first_mac_octet & 0x03 != 0x02 {
        output.push(Candidate::field(
            network_path,
            "guest_mac",
            MalformedProblem::InvalidValue,
        ));
    }
}

fn start_runtime_step_from_launch(identity: &RuntimeLaunchIdentity) -> ReconcileStep {
    ReconcileStep::StartRuntime {
        runtime_incarnation: identity.runtime_incarnation.clone(),
        scope_id: identity.scope_id.clone(),
        launcher_executable: identity.launcher_executable.clone(),
        boot: identity.boot.clone(),
        process_identity_token: identity.process_identity_token.clone(),
        vcpus: identity.vcpus,
        memory_bytes: identity.memory_bytes,
        boot_image_digest: identity.boot_image_digest.clone(),
        guest_config_digest: identity.guest_config_digest.clone(),
        api_socket_path: identity.api_socket_path.clone(),
        vsock_socket_path: identity.vsock_socket_path.clone(),
        guest_cid: identity.guest_cid,
        memory_file_path: identity.memory_file_path.clone(),
        serial_log_path: identity.serial_log_path.clone(),
        vmm_log_path: identity.vmm_log_path.clone(),
        network: identity.network.clone(),
        devices: identity.devices.clone(),
    }
}

#[derive(Clone, Copy)]
enum RuntimeLaunchRequirement {
    Any,
    Absent,
    Present,
}

fn runtime_launch_requirement(step: &ReconcileStep) -> RuntimeLaunchRequirement {
    match step {
        ReconcileStep::AcquireVolume { .. }
        | ReconcileStep::ProvisionRootImage { .. }
        | ReconcileStep::PrepareDevice { .. }
        | ReconcileStep::PrepareNetwork { .. }
        | ReconcileStep::DeleteDisposableRoot { .. }
        | ReconcileStep::Stable {
            state: StableState::Warm | StableState::Cold | StableState::Deleted,
        } => RuntimeLaunchRequirement::Absent,
        ReconcileStep::CloseGate { .. }
        | ReconcileStep::FormatFilesystem { .. }
        | ReconcileStep::DrainInitialization { .. }
        | ReconcileStep::CommitInitialized { .. }
        | ReconcileStep::MountFilesystem { .. }
        | ReconcileStep::StartRuntime { .. }
        | ReconcileStep::PauseRuntime { .. }
        | ReconcileStep::SnapshotWarmRuntime { .. }
        | ReconcileStep::StopRuntime { .. }
        | ReconcileStep::OpenAdmission { .. }
        | ReconcileStep::InstallGate { .. }
        | ReconcileStep::Stable {
            state: StableState::Running | StableState::Suspended,
        } => RuntimeLaunchRequirement::Present,
        ReconcileStep::InspectInventory { .. }
        | ReconcileStep::CloseAdmission { .. }
        | ReconcileStep::DrainPublish { .. }
        | ReconcileStep::CleanupRelease { .. }
        | ReconcileStep::Quarantined => RuntimeLaunchRequirement::Any,
    }
}

fn step_runtime_incarnation(step: &ReconcileStep) -> Option<&RandomId128> {
    match step {
        ReconcileStep::FormatFilesystem { filesystem }
        | ReconcileStep::DrainInitialization { filesystem, .. }
        | ReconcileStep::CommitInitialized { filesystem, .. }
        | ReconcileStep::MountFilesystem { filesystem, .. } => {
            Some(&filesystem.runtime_incarnation)
        }
        ReconcileStep::StartRuntime {
            runtime_incarnation,
            ..
        }
        | ReconcileStep::PauseRuntime {
            runtime_incarnation,
            ..
        }
        | ReconcileStep::SnapshotWarmRuntime {
            runtime_incarnation,
            ..
        }
        | ReconcileStep::StopRuntime {
            runtime_incarnation,
            ..
        }
        | ReconcileStep::OpenAdmission {
            runtime_incarnation,
        } => Some(runtime_incarnation),
        _ => None,
    }
}

fn collect_runtime_launch_cross(
    runtime_incarnation: Option<&RandomId128>,
    runtime_launch: &RuntimeLaunch,
    step: &ReconcileStep,
    base_path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    let launch_path = child(base_path, "runtime_launch");
    let expected_start_runtime_identity = step.start_runtime_launch_identity();
    let exact_absent =
        runtime_incarnation.is_none() && matches!(runtime_launch, RuntimeLaunch::Absent);
    let exact_present =
        runtime_incarnation.is_some() && matches!(runtime_launch, RuntimeLaunch::Present(_));
    match (runtime_incarnation, runtime_launch) {
        (None, RuntimeLaunch::Absent) => {}
        (Some(runtime_incarnation), RuntimeLaunch::Present(identity))
            if identity.runtime_incarnation == *runtime_incarnation =>
        {
            // StartRuntime already validates the same exact bytes at `/step`.
            // Later steps no longer carry them, so their retained identity is
            // validated independently at its durable checkpoint location.
            if expected_start_runtime_identity.as_ref() != Some(identity.as_ref()) {
                let identity_path = child(&launch_path, "identity");
                let launch_step = start_runtime_step_from_launch(identity);
                collect_reconcile_step_cross(&launch_step, &identity_path, false, output);
            }
        }
        _ => output.push(Candidate::at(&launch_path, MalformedProblem::InvalidValue)),
    }

    let presence_is_valid = match runtime_launch_requirement(step) {
        RuntimeLaunchRequirement::Any => true,
        RuntimeLaunchRequirement::Absent => exact_absent,
        RuntimeLaunchRequirement::Present => exact_present,
    };
    if !presence_is_valid {
        output.push(Candidate::at(&launch_path, MalformedProblem::InvalidValue));
    }
    if let Some(step_incarnation) = step_runtime_incarnation(step) {
        if runtime_incarnation != Some(step_incarnation) {
            output.push(Candidate::field(
                base_path,
                "runtime_incarnation",
                MalformedProblem::InvalidValue,
            ));
        }
    }

    if let Some(expected) = expected_start_runtime_identity {
        let step_path = child(base_path, "step");
        let step_is_independently_invalid = output
            .iter()
            .any(|candidate| candidate.path.starts_with(&step_path));
        if !step_is_independently_invalid
            && runtime_launch != &RuntimeLaunch::Present(Box::new(expected))
        {
            output.push(Candidate::at(&launch_path, MalformedProblem::InvalidValue));
        }
    }

    let step_path = child(base_path, "step");
    let filesystem_step_is_independently_invalid = output
        .iter()
        .any(|candidate| candidate.path.starts_with(&step_path));
    if let (Some(filesystem), RuntimeLaunch::Present(launch)) =
        (persistent_filesystem_step_binding(step), runtime_launch)
    {
        if filesystem_step_is_independently_invalid {
            return;
        }
        let exact = launch.runtime_incarnation == filesystem.runtime_incarnation
            && launch
                .devices
                .iter()
                .filter(|device| device.volume_intent_id == filesystem.volume_intent_id)
                .count()
                == 1
            && launch.devices.iter().any(|device| {
                device.disk_kind == DiskKind::Persistent
                    && device.volume_intent_id == filesystem.volume_intent_id
                    && device.disk_id == filesystem.disk_id
                    && device.volume_id == filesystem.volume_id
                    && device.attachment_id == filesystem.attachment_id
                    && device.attachment_epoch == filesystem.attachment_epoch
                    && device.size_bytes == filesystem.size_bytes
                    && device.guest_device == filesystem.guest_device
                    && match &filesystem.initialization {
                        FilesystemInitialization::Initialize {
                            expected_blank_head,
                            ..
                        } => device.expected_head == *expected_blank_head,
                        FilesystemInitialization::Existing => match step {
                            ReconcileStep::MountFilesystem { expected_head, .. } => {
                                device.expected_head == *expected_head
                            }
                            _ => false,
                        },
                    }
            });
        if !exact {
            output.push(Candidate::at(&launch_path, MalformedProblem::InvalidValue));
        }
    }
}

fn persistent_filesystem_step_binding(
    step: &ReconcileStep,
) -> Option<&PersistentFilesystemBinding> {
    match step {
        ReconcileStep::FormatFilesystem { filesystem }
        | ReconcileStep::DrainInitialization { filesystem, .. }
        | ReconcileStep::CommitInitialized { filesystem, .. }
        | ReconcileStep::MountFilesystem { filesystem, .. } => Some(filesystem),
        _ => None,
    }
}

fn validate_runtime_checkpoint(checkpoint: &RuntimeCheckpoint) -> Result<(), ContractError> {
    if let Some(candidate) = choose(collect_checkpoint_arrays(checkpoint)) {
        return Err(malformed(ContractName::RuntimeCheckpoint, candidate));
    }
    let mut cross = Vec::new();
    collect_physical_cross(&checkpoint.processes, &checkpoint.volumes, &[], &mut cross);
    collect_reconcile_step_cross(&checkpoint.step, &path(&["step"]), false, &mut cross);
    collect_runtime_launch_cross(
        checkpoint.runtime_incarnation.as_ref(),
        &checkpoint.runtime_launch,
        &checkpoint.step,
        &[],
        &mut cross,
    );
    collect_close_gate_checkpoint_cross(checkpoint, &mut cross);
    collect_runtime_resource_cross(checkpoint, &[], &mut cross);
    collect_warm_snapshot_cross(
        &checkpoint.warm_snapshot,
        &path(&["warm_snapshot"]),
        &mut cross,
    );
    if !incarnation_matches_state(
        checkpoint.stable_state,
        checkpoint.runtime_incarnation.as_ref(),
    ) {
        cross.push(Candidate::at(&[], MalformedProblem::InvalidValue));
    }
    if let Some(candidate) = choose(cross) {
        return Err(malformed(ContractName::RuntimeCheckpoint, candidate));
    }
    Ok(())
}

trait RuntimeResourceEvidence {
    fn resource_node_id(&self) -> Option<&Id>;
    fn resource_placement_epoch(&self) -> Option<&Epoch>;
    fn resource_runtime_incarnation(&self) -> Option<&RandomId128>;
    fn resource_stable_state(&self) -> Option<StableState>;
    fn resource_step(&self) -> &ReconcileStep;
    fn resource_processes(&self) -> &[ProcessEvidence];
    fn resource_volumes(&self) -> &[ObservedVolume];
    fn resource_mounts(&self) -> &[ObservedMount];
    fn resource_networks(&self) -> &[ObservedNetwork];
    fn resource_guest_transport(&self) -> &GuestTransportEvidence;
    fn resource_lifecycle_admission(&self) -> LifecycleAdmission;
    fn resource_routes_are_empty(&self) -> bool;
}

impl RuntimeResourceEvidence for RuntimeCheckpoint {
    fn resource_node_id(&self) -> Option<&Id> {
        Some(&self.node_id)
    }

    fn resource_placement_epoch(&self) -> Option<&Epoch> {
        Some(&self.placement_epoch)
    }

    fn resource_runtime_incarnation(&self) -> Option<&RandomId128> {
        self.runtime_incarnation.as_ref()
    }

    fn resource_stable_state(&self) -> Option<StableState> {
        self.stable_state
    }

    fn resource_step(&self) -> &ReconcileStep {
        &self.step
    }

    fn resource_processes(&self) -> &[ProcessEvidence] {
        &self.processes
    }

    fn resource_volumes(&self) -> &[ObservedVolume] {
        &self.volumes
    }

    fn resource_mounts(&self) -> &[ObservedMount] {
        &self.mounts
    }

    fn resource_networks(&self) -> &[ObservedNetwork] {
        &self.networks
    }

    fn resource_guest_transport(&self) -> &GuestTransportEvidence {
        &self.guest_transport
    }

    fn resource_lifecycle_admission(&self) -> LifecycleAdmission {
        self.lifecycle_admission
    }

    fn resource_routes_are_empty(&self) -> bool {
        self.route_gates.is_empty()
    }
}

impl RuntimeResourceEvidence for ObservedRuntimeStatus {
    fn resource_node_id(&self) -> Option<&Id> {
        match &self.checkpoint {
            CheckpointEvidence::Valid { node_id, .. } => Some(node_id),
            CheckpointEvidence::Missing { .. } | CheckpointEvidence::Corrupt { .. } => None,
        }
    }

    fn resource_placement_epoch(&self) -> Option<&Epoch> {
        match &self.checkpoint {
            CheckpointEvidence::Valid {
                placement_epoch, ..
            } => Some(placement_epoch),
            CheckpointEvidence::Missing { .. } | CheckpointEvidence::Corrupt { .. } => None,
        }
    }

    fn resource_runtime_incarnation(&self) -> Option<&RandomId128> {
        self.runtime_incarnation.as_ref()
    }

    fn resource_stable_state(&self) -> Option<StableState> {
        self.stable_state
    }

    fn resource_step(&self) -> &ReconcileStep {
        &self.step
    }

    fn resource_processes(&self) -> &[ProcessEvidence] {
        &self.processes
    }

    fn resource_volumes(&self) -> &[ObservedVolume] {
        &self.volumes
    }

    fn resource_mounts(&self) -> &[ObservedMount] {
        &self.mounts
    }

    fn resource_networks(&self) -> &[ObservedNetwork] {
        &self.networks
    }

    fn resource_guest_transport(&self) -> &GuestTransportEvidence {
        &self.guest_transport
    }

    fn resource_lifecycle_admission(&self) -> LifecycleAdmission {
        self.lifecycle_admission
    }

    fn resource_routes_are_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

fn collect_runtime_resource_cross(
    runtime: &impl RuntimeResourceEvidence,
    runtime_path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    let (Some(node_id), Some(placement_epoch)) = (
        runtime.resource_node_id(),
        runtime.resource_placement_epoch(),
    ) else {
        return;
    };
    match runtime.resource_step() {
        ReconcileStep::PrepareNetwork { network, devices } => {
            collect_launch_phase_resource_envelope(runtime, runtime_path, output);
            collect_prepared_device_resource_cross(
                runtime,
                node_id,
                placement_epoch,
                devices,
                runtime_path,
                output,
            );
            if !runtime.resource_networks().is_empty()
                && !runtime_network_is_exact(runtime.resource_networks(), network)
            {
                output.push(Candidate::at(
                    &child(runtime_path, "networks"),
                    MalformedProblem::InvalidValue,
                ));
            }
            if runtime.resource_runtime_incarnation().is_some() {
                output.push(Candidate::field(
                    runtime_path,
                    "runtime_incarnation",
                    MalformedProblem::InvalidValue,
                ));
            }
            if !matches!(
                runtime.resource_guest_transport(),
                GuestTransportEvidence::Unavailable
            ) {
                output.push(Candidate::at(
                    &child(runtime_path, "guest_transport"),
                    MalformedProblem::InvalidValue,
                ));
            }
            if runtime
                .resource_processes()
                .iter()
                .any(|process| matches!(process.role, ProcessRole::Vmm { .. }))
            {
                output.push(Candidate::at(
                    &child(runtime_path, "processes"),
                    MalformedProblem::InvalidValue,
                ));
            }
        }
        ReconcileStep::StartRuntime {
            runtime_incarnation,
            scope_id,
            launcher_executable,
            boot,
            process_identity_token,
            vcpus,
            memory_bytes,
            boot_image_digest,
            guest_config_digest: expected_guest_config_digest,
            api_socket_path,
            vsock_socket_path,
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            guest_cid,
            network,
            devices,
            ..
        } => {
            collect_launch_phase_resource_envelope(runtime, runtime_path, output);
            collect_prepared_device_resource_cross(
                runtime,
                node_id,
                placement_epoch,
                devices,
                runtime_path,
                output,
            );
            if runtime.resource_runtime_incarnation() != Some(runtime_incarnation) {
                output.push(Candidate::field(
                    runtime_path,
                    "runtime_incarnation",
                    MalformedProblem::InvalidValue,
                ));
            }
            if !runtime_network_is_exact(runtime.resource_networks(), network) {
                output.push(Candidate::at(
                    &child(runtime_path, "networks"),
                    MalformedProblem::InvalidValue,
                ));
            }

            let vmm_is_exact = |process: &ProcessEvidence| {
                matches!(
                    &process.role,
                    ProcessRole::Vmm {
                        runtime_incarnation: observed_incarnation,
                    } if observed_incarnation == runtime_incarnation
                ) && process.scope_id == *scope_id
                    && process.executable_path == boot.vmm_executable.path
                    && process.control_socket_path == *api_socket_path
                    && process.state == ProcessState::Running
                    && process.ownership_token
                        == OwnershipTokenEvidence::Valid {
                            ownership_token: process_identity_token.clone(),
                        }
                    && process.control_handshake == ControlHandshakeEvidence::Verified
                    && process.observed_vm_shape.as_ref().is_some_and(|shape| {
                        shape.vcpus == *vcpus
                            && shape.memory_bytes == *memory_bytes
                            && shape.boot_image_digest == *boot_image_digest
                            && shape.guest_config_digest == *expected_guest_config_digest
                    })
            };
            let exact_vmm_count = runtime
                .resource_processes()
                .iter()
                .filter(|process| matches!(process.role, ProcessRole::Vmm { .. }))
                .filter(|process| vmm_is_exact(process))
                .count();
            let observed_vmm_count = runtime
                .resource_processes()
                .iter()
                .filter(|process| matches!(process.role, ProcessRole::Vmm { .. }))
                .count();
            if observed_vmm_count > 1 || exact_vmm_count != observed_vmm_count {
                output.push(Candidate::at(
                    &child(runtime_path, "processes"),
                    MalformedProblem::InvalidValue,
                ));
            }

            match runtime.resource_guest_transport() {
                GuestTransportEvidence::Unavailable => {}
                GuestTransportEvidence::Malformed { .. } if observed_vmm_count == 1 => {}
                GuestTransportEvidence::VsockReady {
                    runtime_incarnation: observed_incarnation,
                    guest_cid: observed_cid,
                    guest_port,
                    guest_agent_protocol_version: ContractVersion::V1,
                    ..
                } if observed_vmm_count == 1
                    && observed_incarnation == runtime_incarnation
                    && observed_cid == guest_cid
                    && *guest_port == GUEST_AGENT_VSOCK_PORT_V1 => {}
                GuestTransportEvidence::Malformed { .. }
                | GuestTransportEvidence::VsockReady { .. } => {
                    output.push(Candidate::at(
                        &child(runtime_path, "guest_transport"),
                        MalformedProblem::InvalidValue,
                    ));
                }
            }

            let launch_paths = [
                &launcher_executable.path,
                &boot.vmm_executable.path,
                &boot.kernel.path,
                api_socket_path,
                vsock_socket_path,
                memory_file_path,
                serial_log_path,
                vmm_log_path,
            ];
            let conflicts_with_planned_path = |candidate: &HostPath| {
                launch_paths
                    .iter()
                    .copied()
                    .chain(boot.initramfs.as_ref().map(|artifact| &artifact.path))
                    .chain(
                        devices
                            .iter()
                            .flat_map(prepared_device_identity_paths)
                            .flatten(),
                    )
                    .chain(
                        devices
                            .iter()
                            .map(|device| &device.serving_process.executable_path),
                    )
                    .any(|planned_path| planned_path == candidate)
            };
            let mount_path_conflict = runtime.resource_mounts().iter().any(|mount| {
                conflicts_with_planned_path(&mount.source_path)
                    || conflicts_with_planned_path(&mount.mount_path)
            });
            if mount_path_conflict {
                output.push(Candidate::at(
                    &child(runtime_path, "step"),
                    MalformedProblem::InvalidValue,
                ));
            }
        }
        ReconcileStep::OpenAdmission {
            runtime_incarnation,
        } => {
            if runtime.resource_runtime_incarnation() != Some(runtime_incarnation) {
                output.push(Candidate::field(
                    runtime_path,
                    "runtime_incarnation",
                    MalformedProblem::InvalidValue,
                ));
            }
            if runtime.resource_stable_state().is_some() {
                output.push(Candidate::field(
                    runtime_path,
                    "stable_state",
                    MalformedProblem::InvalidValue,
                ));
            }
            if runtime.resource_lifecycle_admission() != LifecycleAdmission::Closed {
                output.push(Candidate::field(
                    runtime_path,
                    "lifecycle_admission",
                    MalformedProblem::InvalidValue,
                ));
            }
            if !runtime.resource_routes_are_empty() {
                output.push(Candidate::at(
                    &child(
                        runtime_path,
                        if runtime_path.is_empty() {
                            "route_gates"
                        } else {
                            "routes"
                        },
                    ),
                    MalformedProblem::InvalidValue,
                ));
            }
        }
        _ => {}
    }
}

fn collect_launch_phase_resource_envelope(
    runtime: &impl RuntimeResourceEvidence,
    runtime_path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    if runtime.resource_stable_state().is_some()
        || runtime.resource_lifecycle_admission() != LifecycleAdmission::Closed
        || !runtime.resource_routes_are_empty()
    {
        output.push(Candidate::at(runtime_path, MalformedProblem::InvalidValue));
    }
}

fn collect_prepared_device_resource_cross(
    runtime: &impl RuntimeResourceEvidence,
    node_id: &Id,
    placement_epoch: &Epoch,
    inputs: &[PreparedDeviceInput],
    runtime_path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    let volumes_are_exact = runtime.resource_volumes().len() == inputs.len()
        && inputs.iter().all(|input| {
            let matching = runtime
                .resource_volumes()
                .iter()
                .filter(|volume| volume.volume_id == input.volume_id)
                .collect::<Vec<_>>();
            matching.len() == 1
                && prepared_volume_is_exact(node_id, placement_epoch, input, matching[0])
        });
    if !volumes_are_exact {
        output.push(Candidate::at(
            &child(runtime_path, "volumes"),
            MalformedProblem::InvalidValue,
        ));
    }

    let observed_blockd = runtime
        .resource_processes()
        .iter()
        .filter(|process| matches!(process.role, ProcessRole::Blockd { .. }))
        .collect::<Vec<_>>();
    let blockd_are_exact = observed_blockd.iter().all(|process| {
        inputs
            .iter()
            .filter(|input| prepared_blockd_is_exact(input, process))
            .count()
            == 1
    }) && inputs.iter().all(|input| {
        observed_blockd
            .iter()
            .filter(|process| prepared_blockd_is_exact(input, process))
            .count()
            <= 1
    });
    if !blockd_are_exact {
        output.push(Candidate::at(
            &child(runtime_path, "processes"),
            MalformedProblem::InvalidValue,
        ));
    }
}

fn prepared_volume_is_exact(
    node_id: &Id,
    placement_epoch: &Epoch,
    input: &PreparedDeviceInput,
    observed: &ObservedVolume,
) -> bool {
    let disk_kind_is_exact = match input.disk_kind {
        DiskKind::Root => observed.disk_kind == ObservedDiskKind::Root,
        DiskKind::Persistent => observed.disk_kind == ObservedDiskKind::Persistent,
    };
    let authority_is_exact = matches!(
        &observed.authority,
        VolumeAuthorityEvidence::Owned {
            attachment_id,
            attachment_epoch,
            head,
        } if attachment_id == &input.attachment_id
            && attachment_epoch == &input.attachment_epoch
            && head == &input.expected_head
    );
    let lineage_is_exact = matches!(
        observed.local_lineages.as_slice(),
        [lineage]
            if lineage.attachment_id == input.attachment_id
                && lineage.attachment_epoch == input.attachment_epoch
                && lineage.acquire_origin == input.acquire_origin
                && lineage.node_id == *node_id
                && lineage.placement_epoch == *placement_epoch
                && lineage.local_durable_generation == input.expected_head.generation
                && lineage.remote_durable_generation == input.expected_head.generation
                && lineage.data_directory == input.serving_process.data_directory
                && lineage.pending_pack_count.get() == 0
                && !lineage.fenced
                && lineage.state == LocalLineageState::Active
    );
    let device_projection_is_exact = match observed.devices.as_slice() {
        [] => true,
        [device] => prepared_device_is_exact(input, device),
        _ => false,
    };
    observed.volume_intent_id.as_ref() == Some(&input.volume_intent_id)
        && observed.disk_id.as_ref() == Some(&input.disk_id)
        && disk_kind_is_exact
        && observed.size_bytes == Some(input.size_bytes)
        && observed.durability == Some(input.durability)
        && authority_is_exact
        && lineage_is_exact
        && device_projection_is_exact
}

fn prepared_blockd_is_exact(input: &PreparedDeviceInput, observed: &ProcessEvidence) -> bool {
    matches!(
        &observed.role,
        ProcessRole::Blockd {
            volume_id,
            attachment_id,
            attachment_epoch,
        } if volume_id == &input.volume_id
            && attachment_id == &input.attachment_id
            && attachment_epoch == &input.attachment_epoch
    ) && observed.executable_path == input.serving_process.executable_path
        && observed.scope_id == input.serving_process.scope_id
        && observed.control_socket_path == input.serving_process.control_socket_path
        && observed.state == ProcessState::Running
        && observed.ownership_token
            == OwnershipTokenEvidence::Valid {
                ownership_token: input.serving_process.process_identity_token.clone(),
            }
        && observed.control_handshake == ControlHandshakeEvidence::Verified
        && observed.observed_vm_shape.is_none()
}

fn runtime_network_is_exact(
    networks: &[ObservedNetwork],
    expected: &RuntimeNetworkIdentity,
) -> bool {
    let [observed] = networks else {
        return false;
    };
    observed.kind == expected.network_config.kind
        && observed.network_id == expected.network_config.network_id
        && observed.guest_mac == expected.network_config.guest_mac
        && observed.guest_ipv4 == expected.network_config.guest_ipv4
        && observed.prefix_length == expected.network_config.prefix_length
        && observed.gateway_ipv4 == expected.network_config.gateway_ipv4
        && observed.tap_name == expected.tap_name
        && observed.ownership_token
            == OwnershipTokenEvidence::Valid {
                ownership_token: expected.ownership_token.clone(),
            }
}

fn prepared_device_is_exact(input: &PreparedDeviceInput, observed: &ObservedDevice) -> bool {
    match (&input.frontend, observed) {
        (
            PrepareDeviceFrontend::KernelNbd { device_path, .. },
            ObservedDevice::KernelNbd {
                guest_device: observed_guest_device,
                device_path: observed_device_path,
                ownership_token: observed_token,
            },
        ) => {
            input.guest_device == *observed_guest_device
                && device_path == observed_device_path
                && observed_token
                    == &OwnershipTokenEvidence::Valid {
                        ownership_token: input.ownership_token.clone(),
                    }
        }
        (
            PrepareDeviceFrontend::VhostUserBlk { socket_path, .. },
            ObservedDevice::VhostUserBlk {
                guest_device: observed_guest_device,
                socket_path: observed_socket_path,
                ownership_token: observed_token,
            },
        ) => {
            input.guest_device == *observed_guest_device
                && socket_path == observed_socket_path
                && observed_token
                    == &OwnershipTokenEvidence::Valid {
                        ownership_token: input.ownership_token.clone(),
                    }
        }
        _ => false,
    }
}

fn collect_close_gate_checkpoint_cross(
    checkpoint: &RuntimeCheckpoint,
    output: &mut Vec<Candidate>,
) {
    let ReconcileStep::CloseGate {
        endpoint_id,
        route_epoch,
    } = &checkpoint.step
    else {
        return;
    };
    let matching_entries = checkpoint
        .route_gates
        .iter()
        .filter(|entry| {
            entry.binding.endpoint_id == *endpoint_id && entry.binding.route_epoch == *route_epoch
        })
        .count();
    if matching_entries != 1 {
        output.push(Candidate::at(&[], MalformedProblem::InvalidValue));
    }
}

fn validate_node_cleanup_checkpoint(
    checkpoint: &NodeCleanupCheckpoint,
) -> Result<(), ContractError> {
    let mut cross = Vec::new();
    collect_cleanup_cross(&checkpoint.cleanup, &path(&["cleanup"]), true, &mut cross);
    match &checkpoint.cleanup.target {
        CleanupTarget::CheckpointFile { node_id, .. }
            if node_id == &checkpoint.node_id
                && checkpoint.cleanup.inventory_session.node_id == checkpoint.node_id => {}
        _ => cross.push(Candidate::at(&[], MalformedProblem::InvalidValue)),
    }
    if let Some(candidate) = choose(cross) {
        return Err(malformed(ContractName::NodeCleanupCheckpoint, candidate));
    }
    Ok(())
}

fn validate_node_observation(
    observation: &NodeObservation,
    compare_digest: bool,
) -> Result<(), ContractError> {
    let contract = ContractName::NodeObservation;
    let mut arrays = Vec::new();
    collect_unique_order(
        &observation.loaded_kids,
        &path(&["loaded_kids"]),
        |kid| kid.as_str().as_bytes().to_vec(),
        &mut arrays,
    );
    collect_unique_order(
        &observation.runtimes,
        &path(&["runtimes"]),
        |runtime| runtime.cat_id.as_str().as_bytes().to_vec(),
        &mut arrays,
    );
    for (index, runtime) in observation.runtimes.iter().enumerate() {
        collect_runtime_arrays(runtime, &indexed(&path(&["runtimes"]), index), &mut arrays);
    }
    collect_order(
        &observation.residue,
        &path(&["residue"]),
        residue_key,
        &mut arrays,
    );
    if has_duplicate(observation.residue.iter().filter_map(|residue| {
        let NodeResidue::Mount {
            source_path,
            mount_path,
            ..
        } = residue
        else {
            return None;
        };
        Some((mount_path.as_str(), source_path.as_str()))
    })) || has_duplicate(observation.residue.iter().filter_map(|residue| {
        let NodeResidue::RouteGate {
            binding,
            gate,
            active_guards,
            cancellation_pending,
            ..
        } = residue
        else {
            return None;
        };
        Some((
            canonical_item(binding),
            match gate {
                RouteGateState::Active => 0,
                RouteGateState::Closed => 1,
            },
            *active_guards,
            *cancellation_pending,
        ))
    })) {
        arrays.push(Candidate::at(
            &path(&["residue"]),
            MalformedProblem::DuplicateIdentity,
        ));
    }
    collect_inventory_collisions(observation, &mut arrays);
    if let Some(candidate) = choose(arrays) {
        return Err(malformed(contract, candidate));
    }

    let mut cross = Vec::new();
    let ring_available = match (
        observation.key_ring_version,
        observation.key_ring_digest.as_ref(),
    ) {
        (None, None) => {
            if !observation.loaded_kids.is_empty() {
                cross.push(Candidate::at(&[], MalformedProblem::InvalidValue));
            }
            false
        }
        (Some(_), Some(_)) => true,
        _ => {
            cross.push(Candidate::at(&[], MalformedProblem::InvalidValue));
            false
        }
    };
    if observation.complete_inventory {
        if observation.inventory_digest.is_none() || observation.inventory_read_position.is_none() {
            cross.push(Candidate::at(&[], MalformedProblem::InvalidValue));
        }
    } else if observation.inventory_digest.is_some()
        || observation.inventory_read_position.is_some()
        || !observation.residue.is_empty()
    {
        cross.push(Candidate::at(&[], MalformedProblem::InvalidValue));
    }
    for (index, runtime) in observation.runtimes.iter().enumerate() {
        collect_runtime_cross(
            runtime,
            observation.complete_inventory,
            &indexed(&path(&["runtimes"]), index),
            &mut cross,
        );
    }
    collect_residue_cross(&observation.residue, &path(&["residue"]), &mut cross);
    if let Some(candidate) = choose(cross) {
        return Err(malformed(contract, candidate));
    }
    if compare_digest {
        if observation.complete_inventory
            && observation
                .inventory_digest
                .as_ref()
                .is_some_and(|claim| unchecked_inventory_digest(observation) != *claim)
        {
            return Err(malformed(
                contract,
                Candidate::field(&[], "inventory_digest", MalformedProblem::InvalidValue),
            ));
        }
        if ring_available {
            let version = observation
                .key_ring_version
                .expect("ring availability checked");
            if observation.key_ring_digest.as_ref().is_some_and(|claim| {
                unchecked_key_ring_digest(version, &observation.loaded_kids) != *claim
            }) {
                return Err(malformed(
                    contract,
                    Candidate::field(&[], "key_ring_digest", MalformedProblem::InvalidValue),
                ));
            }
        }
    }
    Ok(())
}

fn validate_operation(operation: &Operation) -> Result<(), ContractError> {
    let contract = ContractName::Operation;
    let mut arrays = Vec::new();
    if let Some(OperationTerminal::Failed { error, .. }) = &operation.terminal {
        match error.as_ref() {
            OperationFailure::PreconditionFailed { reason } => {
                collect_precondition_arrays(
                    reason,
                    &path(&["terminal", "error", "reason"]),
                    &mut arrays,
                );
            }
            OperationFailure::Quarantined { reason } => collect_quarantine_arrays(
                reason,
                &path(&["terminal", "error", "reason"]),
                &mut arrays,
            ),
            OperationFailure::HostLost { .. } => {}
        }
    }
    if let Some(candidate) = choose(arrays) {
        return Err(malformed(contract, candidate));
    }

    let mut cross = Vec::new();
    if operation.updated_at_unix_ms.get() < operation.created_at_unix_ms.get() {
        cross.push(Candidate::at(&[], MalformedProblem::InvalidValue));
    }
    let phase_matches = matches!(
        (&operation.phase, &operation.terminal),
        (OperationPhase::Pending, None)
            | (
                OperationPhase::Succeeded,
                Some(OperationTerminal::Succeeded { .. })
            )
            | (
                OperationPhase::Failed,
                Some(OperationTerminal::Failed { .. })
            )
            | (
                OperationPhase::Superseded,
                Some(OperationTerminal::Superseded { .. })
            )
    );
    if !phase_matches {
        cross.push(Candidate::at(&[], MalformedProblem::InvalidValue));
    }
    if let Some(terminal) = &operation.terminal {
        let completed_at = match terminal {
            OperationTerminal::Succeeded {
                completed_at_unix_ms,
                ..
            }
            | OperationTerminal::Failed {
                completed_at_unix_ms,
                ..
            }
            | OperationTerminal::Superseded {
                completed_at_unix_ms,
                ..
            } => completed_at_unix_ms,
        };
        if completed_at != &operation.updated_at_unix_ms {
            cross.push(Candidate::at(&[], MalformedProblem::InvalidValue));
        }
        match terminal {
            OperationTerminal::Succeeded { result, .. } => {
                if result.observed_target != operation.target
                    || !target_matches_incarnation(
                        result.observed_target,
                        result.runtime_incarnation.as_ref(),
                    )
                {
                    cross.push(Candidate::at(&[], MalformedProblem::InvalidValue));
                }
                if result.node_id != operation.placement.node_id {
                    cross.push(Candidate::field(
                        &path(&["terminal", "result"]),
                        "node_id",
                        MalformedProblem::InvalidValue,
                    ));
                }
            }
            OperationTerminal::Failed { error, .. } => match error.as_ref() {
                OperationFailure::HostLost { node_id, .. } => {
                    if node_id != &operation.placement.node_id {
                        cross.push(Candidate::field(
                            &path(&["terminal", "error"]),
                            "node_id",
                            MalformedProblem::InvalidValue,
                        ));
                    }
                }
                OperationFailure::PreconditionFailed { reason } => {
                    if let PreconditionFailureReason::PlacementRejected {
                        node_id,
                        placement_epoch,
                        ..
                    } = reason
                    {
                        if node_id != &operation.placement.node_id {
                            cross.push(Candidate::field(
                                &path(&["terminal", "error", "reason"]),
                                "node_id",
                                MalformedProblem::InvalidValue,
                            ));
                        }
                        if placement_epoch != &operation.placement.placement_epoch {
                            cross.push(Candidate::field(
                                &path(&["terminal", "error", "reason"]),
                                "placement_epoch",
                                MalformedProblem::InvalidValue,
                            ));
                        }
                    }
                }
                OperationFailure::Quarantined { reason } => collect_quarantine_cross(
                    reason,
                    &path(&["terminal", "error", "reason"]),
                    &mut cross,
                ),
            },
            OperationTerminal::Superseded {
                superseded_by_revision,
                superseded_by_operation_id,
                ..
            } => {
                if superseded_by_revision.get() <= operation.desired_revision.get()
                    || superseded_by_operation_id == &operation.operation_id
                {
                    cross.push(Candidate::at(&[], MalformedProblem::InvalidValue));
                }
            }
        }
    }
    if let Some(candidate) = choose(cross) {
        return Err(malformed(contract, candidate));
    }
    Ok(())
}

fn validate_contract_error(error: &ContractError) -> Result<(), ContractError> {
    let valid = match error.error.as_ref() {
        ContractErrorDetail::StaleSession {
            presented_agent_session_epoch,
            current_agent_session_epoch,
            ..
        } => presented_agent_session_epoch < current_agent_session_epoch,
        ContractErrorDetail::WrongSession {
            expected,
            presented,
        } => {
            expected != presented
                && presented.agent_session_epoch.get() >= expected.agent_session_epoch.get()
        }
        ContractErrorDetail::RegistrationAttemptConflict {
            expected,
            presented,
            ..
        } => expected != presented,
        ContractErrorDetail::GuestConfigMismatch {
            expected_guest_config_digest,
            presented_guest_config_digest,
            ..
        } => expected_guest_config_digest != presented_guest_config_digest,
        ContractErrorDetail::StaleObservationSequence {
            presented_heartbeat_sequence,
            last_accepted_heartbeat_sequence,
            ..
        } => presented_heartbeat_sequence < last_accepted_heartbeat_sequence,
        ContractErrorDetail::SessionExpired {
            lease_deadline_unix_ms,
            server_time_unix_ms,
            ..
        } => server_time_unix_ms >= lease_deadline_unix_ms,
        ContractErrorDetail::StaleDesiredReadSequence {
            presented_request_sequence,
            last_request_sequence,
            ..
        } => presented_request_sequence < last_request_sequence,
        ContractErrorDetail::WrongDesiredReadSequence {
            expected_request_sequence,
            presented_request_sequence,
            ..
        } => presented_request_sequence > expected_request_sequence,
        ContractErrorDetail::AssignedSetLimitExceeded {
            limit,
            maximum,
            observed_at_least,
            ..
        } => match limit {
            AssignedSetLimit::DesiredSpecs => {
                maximum.get() == 1024 && observed_at_least.get() == 1025
            }
            AssignedSetLimit::WireBytes => {
                maximum.get() == 16_777_216 && observed_at_least.get() == 16_777_217
            }
        },
        ContractErrorDetail::StaleInventoryReadPosition {
            presented_read_position,
            current_read_position,
            ..
        } => presented_read_position < current_read_position,
        ContractErrorDetail::WrongInventoryReadPosition {
            current_read_position,
            presented_read_position,
            ..
        } => presented_read_position > current_read_position,
        ContractErrorDetail::InventoryReadPositionExpired {
            expires_at_unix_ms,
            server_time_unix_ms,
            ..
        } => server_time_unix_ms >= expires_at_unix_ms,
        ContractErrorDetail::AssignedRuntimeBindingMismatch {
            expected,
            presented,
            ..
        } => presented.as_ref() != Some(expected),
        ContractErrorDetail::StaleInventoryEpoch {
            presented_inventory_epoch,
            current_inventory_epoch,
            ..
        } => presented_inventory_epoch <= current_inventory_epoch,
        ContractErrorDetail::WrongInventoryEpoch {
            expected_inventory_epoch,
            presented_inventory_epoch,
            ..
        } => presented_inventory_epoch > expected_inventory_epoch,
        ContractErrorDetail::StaleRevision {
            presented_revision,
            current_revision,
            ..
        } => presented_revision < current_revision,
        ContractErrorDetail::WrongRevision {
            expected_revision,
            presented_revision,
            ..
        } => presented_revision > expected_revision,
        ContractErrorDetail::RevisionDigestConflict {
            expected_digest,
            presented_digest,
            ..
        } => expected_digest != presented_digest,
        ContractErrorDetail::WrongPlacement {
            expected,
            presented,
            ..
        } => expected != presented,
        ContractErrorDetail::UnsupportedVersion {
            supported_version,
            presented_version,
            ..
        } => supported_version != presented_version,
        ContractErrorDetail::LimitExceeded {
            json_pointer,
            limit,
            maximum,
            observed_at_least,
            ..
        } => {
            maximum
                .get()
                .checked_add(1)
                .is_some_and(|expected| observed_at_least.get() == expected)
                && (*limit != LimitKind::WireBytes || json_pointer.as_str().is_empty())
        }
        ContractErrorDetail::MalformedPayload {
            json_pointer,
            problem: MalformedProblem::InvalidUtf8 | MalformedProblem::InvalidJson,
            ..
        } => json_pointer.as_str().is_empty(),
        ContractErrorDetail::IdempotencyConflict {
            expected_request_fingerprint,
            presented_request_fingerprint,
            ..
        } => expected_request_fingerprint != presented_request_fingerprint,
        _ => true,
    };
    if !valid {
        return Err(malformed(
            ContractName::ContractError,
            Candidate::at(&path(&["error"]), MalformedProblem::InvalidValue),
        ));
    }
    Ok(())
}

fn collect_precondition_arrays(
    reason: &PreconditionFailureReason,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    if let PreconditionFailureReason::Busy {
        endpoint_guards, ..
    } = reason
    {
        collect_endpoint_guard_arrays(endpoint_guards, &child(path, "endpoint_guards"), output);
    }
}

fn validate_scalar_order<T: Ord>(
    items: &[T],
    contract: ContractName,
    path: &[PathSegment],
) -> Result<(), ContractError> {
    if items.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(malformed(
            contract,
            Candidate::at(path, MalformedProblem::DuplicateIdentity),
        ));
    }
    if items.windows(2).any(|pair| pair[0] > pair[1]) {
        return Err(malformed(
            contract,
            Candidate::at(path, MalformedProblem::NonCanonicalOrder),
        ));
    }
    Ok(())
}

fn path(keys: &[&str]) -> Vec<PathSegment> {
    keys.iter()
        .map(|key| PathSegment::Key((*key).to_owned()))
        .collect()
}

fn indexed(path: &[PathSegment], index: usize) -> Vec<PathSegment> {
    let mut result = path.to_vec();
    result.push(PathSegment::Index(index));
    result
}

fn ipv4_integer(address: &Ipv4Address) -> u32 {
    let octets = address
        .as_str()
        .parse::<std::net::Ipv4Addr>()
        .expect("validated Ipv4Address parses")
        .octets();
    u32::from_be_bytes(octets)
}

fn has_duplicate<T: Ord>(values: impl IntoIterator<Item = T>) -> bool {
    let mut seen = BTreeSet::new();
    values.into_iter().any(|value| !seen.insert(value))
}

fn collect_unique_order<T, K>(
    items: &[T],
    path: &[PathSegment],
    key: impl Fn(&T) -> K,
    output: &mut Vec<Candidate>,
) where
    K: Ord,
{
    if has_duplicate(items.iter().map(&key)) {
        output.push(Candidate::at(path, MalformedProblem::DuplicateIdentity));
    }
    if items.windows(2).any(|pair| key(&pair[0]) >= key(&pair[1])) {
        output.push(Candidate::at(path, MalformedProblem::NonCanonicalOrder));
    }
}

fn canonical_item<T: serde::Serialize>(item: &T) -> Vec<u8> {
    value_bytes(&serde_json::to_value(item).expect("typed contracts are serializable"))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum SortPart {
    Number(u64),
    Bytes(Vec<u8>),
}

fn bytes(value: &str) -> SortPart {
    SortPart::Bytes(value.as_bytes().to_vec())
}

fn canonical_part<T: serde::Serialize>(value: &T) -> SortPart {
    SortPart::Bytes(canonical_item(value))
}

fn collect_order<T>(
    items: &[T],
    path: &[PathSegment],
    key: impl Fn(&T) -> Vec<SortPart>,
    output: &mut Vec<Candidate>,
) {
    collect_unique_order(items, path, key, output);
}

fn process_key(process: &ProcessEvidence) -> Vec<SortPart> {
    let mut key = match &process.role {
        ProcessRole::Vmm {
            runtime_incarnation,
        } => vec![SortPart::Number(0), bytes(runtime_incarnation.as_str())],
        ProcessRole::Blockd {
            volume_id,
            attachment_id,
            attachment_epoch,
        } => vec![
            SortPart::Number(1),
            bytes(volume_id.as_str()),
            SortPart::Number(attachment_epoch.get()),
            bytes(attachment_id.as_str()),
        ],
    };
    key.extend([
        SortPart::Number(process.process_start_time_ticks.get()),
        SortPart::Number(u64::from(process.process_id)),
        canonical_part(process),
    ]);
    key
}

fn device_key(device: &ObservedDevice) -> Vec<SortPart> {
    let (rank, physical_path, guest_device) = match device {
        ObservedDevice::KernelNbd {
            device_path,
            guest_device,
            ..
        } => (0, device_path, guest_device),
        ObservedDevice::VhostUserBlk {
            socket_path,
            guest_device,
            ..
        } => (1, socket_path, guest_device),
    };
    vec![
        SortPart::Number(rank),
        bytes(physical_path.as_str()),
        bytes(guest_device.serial.as_str()),
        SortPart::Number(u64::from(guest_device.slot)),
        canonical_part(device),
    ]
}

fn condition_ranks(condition: &Condition) -> (u64, u64) {
    match condition {
        Condition::Ready { .. } => (0, 0),
        Condition::Progressing { .. } => (1, 0),
        Condition::Blocked { reason } => (
            2,
            match reason {
                BlockedReason::IncompleteInventory { .. } => 0,
                BlockedReason::SupersededByAnotherNode { .. } => 1,
                BlockedReason::ActiveGuards { .. } => 2,
                BlockedReason::VolumeAuthorityUnavailable { .. } => 3,
                BlockedReason::RemoteDurabilityLag { .. } => 4,
                BlockedReason::AuthorizationUnavailable { .. } => 5,
                BlockedReason::HostRejoinPending { .. } => 6,
                BlockedReason::ControlPlaneUnavailable { .. } => 7,
                BlockedReason::KeyRingUnavailable { .. } => 8,
                BlockedReason::RootImageUnavailable { .. } => 9,
            },
        ),
        Condition::PreconditionFailed { reason } => (
            3,
            match reason {
                PreconditionFailureReason::Busy { .. } => 0,
                PreconditionFailureReason::MustBeCold { .. } => 1,
                PreconditionFailureReason::PlacementRejected { .. } => 2,
            },
        ),
        Condition::Degraded { reason } => (
            4,
            match reason {
                DegradedReason::SourceUnavailable { .. } => 0,
                DegradedReason::AttestationRefreshFailed { .. } => 1,
            },
        ),
        Condition::Quarantined { reason } => (5, quarantine_rank(reason)),
        Condition::DataLossPossible { .. } => (6, 0),
    }
}

fn quarantine_rank(reason: &QuarantineReason) -> u64 {
    match reason {
        QuarantineReason::SpecDigestConflict { .. } => 0,
        QuarantineReason::CheckpointCorrupt { .. } => 1,
        QuarantineReason::RuntimeIdentityConflict { .. } => 2,
        QuarantineReason::DuplicateRuntime { .. } => 3,
        QuarantineReason::ProcessIdentityConflict { .. } => 4,
        QuarantineReason::VolumeIdentityConflict { .. } => 5,
        QuarantineReason::LocalLineageConflict { .. } => 6,
        QuarantineReason::LocalLineageCorrupt { .. } => 7,
        QuarantineReason::DuplicateWriter { .. } => 8,
        QuarantineReason::DuplicateDevice { .. } => 9,
        QuarantineReason::DuplicateMount { .. } => 10,
        QuarantineReason::DuplicateNetwork { .. } => 11,
        QuarantineReason::DuplicateRoute { .. } => 12,
        QuarantineReason::InvalidOwnershipToken { .. } => 13,
        QuarantineReason::UnattributedNodeResidue { .. } => 14,
        QuarantineReason::FilesystemIdentityConflict { .. } => 15,
        QuarantineReason::UnknownPersistentDisk { .. } => 16,
        QuarantineReason::WarmSnapshotConflict { .. } => 17,
        QuarantineReason::RouteGateConflict { .. } => 18,
        QuarantineReason::RootProvisionConflict { .. } => 19,
    }
}

fn collect_endpoint_guard_arrays(
    guards: &[EndpointGuardCount],
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    collect_unique_order(
        guards,
        path,
        |guard| guard.endpoint_id.as_str().as_bytes().to_vec(),
        output,
    );
}

fn collect_require_idle_arrays(
    require_idle: &RequireIdleCheckpoint,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    if let RequireIdleCheckpoint::Busy {
        endpoint_guards, ..
    } = require_idle
    {
        collect_endpoint_guard_arrays(endpoint_guards, &child(path, "endpoint_guards"), output);
    }
}

fn collect_step_arrays(step: &ReconcileStep, path: &[PathSegment], output: &mut Vec<Candidate>) {
    match step {
        ReconcileStep::SnapshotWarmRuntime { source_heads, .. } => collect_unique_order(
            source_heads,
            &child(path, "source_heads"),
            |head| head.volume_id.as_str().as_bytes().to_vec(),
            output,
        ),
        ReconcileStep::PrepareDevice { devices }
        | ReconcileStep::PrepareNetwork { devices, .. }
        | ReconcileStep::StartRuntime { devices, .. } => {
            collect_prepared_device_arrays(devices, &child(path, "devices"), output);
        }
        _ => {}
    }
}

fn collect_prepared_device_arrays(
    devices: &[PreparedDeviceInput],
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    collect_unique_order(devices, path, |device| device.guest_device.slot, output);
    let duplicate_scalar_identity =
        has_duplicate(devices.iter().map(|device| &device.volume_intent_id))
            || has_duplicate(devices.iter().map(|device| &device.disk_id))
            || has_duplicate(devices.iter().map(|device| &device.volume_id))
            || has_duplicate(devices.iter().map(|device| &device.attachment_id))
            || has_duplicate(devices.iter().map(|device| &device.guest_device.serial))
            || has_duplicate(devices.iter().flat_map(|device| {
                [
                    &device.ownership_token,
                    &device.serving_process.process_identity_token,
                ]
            }))
            || has_duplicate(
                devices
                    .iter()
                    .map(|device| &device.serving_process.scope_id),
            );
    let duplicate_path_identity = has_duplicate(
        devices
            .iter()
            .flat_map(prepared_device_identity_paths)
            .flatten(),
    );
    if duplicate_scalar_identity || duplicate_path_identity {
        output.push(Candidate::at(path, MalformedProblem::DuplicateIdentity));
    }
}

fn prepared_device_authority_path(device: &PreparedDeviceInput) -> &HostPath {
    match device.serving_authority.as_ref() {
        ServingAuthorityProvenance::AfterRootProvision { handoff } => &handoff.record.path,
        ServingAuthorityProvenance::DirectAuthorizedAttachment { authorization, .. } => {
            &authorization.path
        }
    }
}

fn prepared_device_frontend_paths(device: &PreparedDeviceInput) -> (&HostPath, Option<&HostPath>) {
    match &device.frontend {
        PrepareDeviceFrontend::KernelNbd {
            listener_socket_path,
            device_path,
            ..
        } => (listener_socket_path, Some(device_path)),
        PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => (socket_path, None),
    }
}

fn prepared_device_identity_paths(device: &PreparedDeviceInput) -> [Option<&HostPath>; 5] {
    let (first_frontend, second_frontend) = prepared_device_frontend_paths(device);
    [
        Some(prepared_device_authority_path(device)),
        Some(&device.serving_process.control_socket_path),
        Some(&device.serving_process.data_directory),
        Some(first_frontend),
        second_frontend,
    ]
}

fn collect_prepared_devices_cross(
    devices: &[PreparedDeviceInput],
    path: &[PathSegment],
    vcpus: Option<u32>,
    output: &mut Vec<Candidate>,
) {
    for (index, device) in devices.iter().enumerate() {
        let device_path = indexed(path, index);
        collect_device_kind_authority_cross(
            device.disk_kind,
            &device.serving_authority,
            &device_path,
            output,
        );
        collect_prepared_device_cross(
            &device.expected_head,
            &device.ownership_token,
            &device.serving_authority,
            &device.serving_process,
            &device.frontend,
            &device_path,
            output,
        );
    }
    if devices.is_empty()
        || devices.iter().enumerate().any(|(index, device)| {
            usize::from(device.guest_device.slot) != index
                || match index {
                    0 => device.disk_kind != DiskKind::Root,
                    _ => device.disk_kind != DiskKind::Persistent,
                }
        })
    {
        output.push(Candidate::at(path, MalformedProblem::InvalidValue));
    }

    let kernel = devices
        .iter()
        .filter_map(|device| match &device.frontend {
            PrepareDeviceFrontend::KernelNbd { direct, .. } => Some(*direct),
            PrepareDeviceFrontend::VhostUserBlk { .. } => None,
        })
        .collect::<Vec<_>>();
    let vhost = devices
        .iter()
        .filter_map(|device| match &device.frontend {
            PrepareDeviceFrontend::KernelNbd { .. } => None,
            PrepareDeviceFrontend::VhostUserBlk {
                queues, queue_size, ..
            } => Some((*queues, *queue_size)),
        })
        .collect::<Vec<_>>();
    let mixed_frontends = !kernel.is_empty() && !vhost.is_empty();
    let inconsistent_kernel = kernel
        .first()
        .is_some_and(|first| kernel.iter().any(|direct| direct != first));
    let inconsistent_vhost = vhost
        .first()
        .is_some_and(|first| vhost.iter().any(|parameters| parameters != first));
    let too_many_queues =
        vcpus.is_some_and(|vcpus| vhost.iter().any(|(queues, _)| u32::from(*queues) > vcpus));
    let identity_paths = devices
        .iter()
        .flat_map(prepared_device_identity_paths)
        .flatten()
        .collect::<Vec<_>>();
    let executable_alias = devices
        .iter()
        .any(|device| identity_paths.contains(&&device.serving_process.executable_path));
    if mixed_frontends
        || inconsistent_kernel
        || inconsistent_vhost
        || too_many_queues
        || executable_alias
    {
        output.push(Candidate::at(path, MalformedProblem::InvalidValue));
    }
}

fn collect_volume_arrays(
    volume: &ObservedVolume,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    let lineages_path = child(path, "local_lineages");
    collect_order(
        &volume.local_lineages,
        &lineages_path,
        |lineage| {
            vec![
                SortPart::Number(lineage.attachment_epoch.get()),
                bytes(lineage.attachment_id.as_str()),
                bytes(lineage.data_directory.as_str()),
                canonical_part(lineage),
            ]
        },
        output,
    );
    if has_duplicate(
        volume
            .local_lineages
            .iter()
            .map(|lineage| &lineage.data_directory),
    ) {
        output.push(Candidate::at(
            &lineages_path,
            MalformedProblem::DuplicateIdentity,
        ));
    }
    let devices_path = child(path, "devices");
    collect_order(&volume.devices, &devices_path, device_key, output);
    if has_duplicate(volume.devices.iter().map(|device| match device {
        ObservedDevice::KernelNbd { device_path, .. } => device_path,
        ObservedDevice::VhostUserBlk { socket_path, .. } => socket_path,
    })) {
        output.push(Candidate::at(
            &devices_path,
            MalformedProblem::DuplicateIdentity,
        ));
    }
}

fn collect_condition_arrays(
    condition: &Condition,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    match condition {
        Condition::Progressing { reason } => {
            let ProgressingReason::ReconcileStep { step } = reason;
            collect_step_arrays(step, &child(&child(path, "reason"), "step"), output);
        }
        Condition::Blocked { reason } => match reason {
            BlockedReason::IncompleteInventory {
                unavailable_sources,
            } => collect_unique_order(
                unavailable_sources,
                &child(&child(path, "reason"), "unavailable_sources"),
                |source| *source,
                output,
            ),
            BlockedReason::ActiveGuards {
                endpoint_guards, ..
            } => collect_endpoint_guard_arrays(
                endpoint_guards,
                &child(&child(path, "reason"), "endpoint_guards"),
                output,
            ),
            BlockedReason::VolumeAuthorityUnavailable { volume_ids } => collect_unique_order(
                volume_ids,
                &child(&child(path, "reason"), "volume_ids"),
                |volume_id| volume_id.as_str().as_bytes().to_vec(),
                output,
            ),
            _ => {}
        },
        Condition::PreconditionFailed { reason } => {
            if let PreconditionFailureReason::Busy {
                endpoint_guards, ..
            } = reason
            {
                collect_endpoint_guard_arrays(
                    endpoint_guards,
                    &child(&child(path, "reason"), "endpoint_guards"),
                    output,
                );
            }
        }
        Condition::Degraded { reason } => {
            if let DegradedReason::SourceUnavailable { sources, .. } = reason {
                collect_unique_order(
                    sources,
                    &child(&child(path, "reason"), "sources"),
                    |source| *source,
                    output,
                );
            }
        }
        Condition::Quarantined { reason } => {
            collect_quarantine_arrays(reason, &child(path, "reason"), output);
        }
        Condition::Ready { .. } | Condition::DataLossPossible { .. } => {}
    }
}

fn collect_quarantine_arrays(
    reason: &QuarantineReason,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    match reason {
        QuarantineReason::RuntimeIdentityConflict {
            observed_incarnations,
            ..
        }
        | QuarantineReason::DuplicateRuntime {
            observed_incarnations,
        } => collect_unique_order(
            observed_incarnations,
            &child(path, "observed_incarnations"),
            |incarnation| incarnation.as_str().as_bytes().to_vec(),
            output,
        ),
        QuarantineReason::ProcessIdentityConflict { process_ids, .. } => collect_unique_order(
            process_ids,
            &child(path, "process_ids"),
            |process_id| *process_id,
            output,
        ),
        QuarantineReason::DuplicateWriter {
            observed_attachments,
            ..
        } => collect_unique_order(
            observed_attachments,
            &child(path, "observed_attachments"),
            |attachment| {
                (
                    attachment.attachment_epoch.get(),
                    attachment.attachment_id.as_str().to_owned(),
                )
            },
            output,
        ),
        _ => {}
    }
}

fn collect_runtime_arrays(
    runtime: &ObservedRuntimeStatus,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    collect_step_arrays(&runtime.step, &child(path, "step"), output);
    if let CheckpointEvidence::Valid {
        step,
        runtime_launch,
        require_idle,
        ..
    } = &runtime.checkpoint
    {
        let checkpoint_path = child(path, "checkpoint");
        collect_step_arrays(step, &child(&checkpoint_path, "step"), output);
        if let RuntimeLaunch::Present(identity) = runtime_launch.as_ref() {
            if step.start_runtime_launch_identity().as_ref() != Some(identity.as_ref()) {
                collect_prepared_device_arrays(
                    &identity.devices,
                    &child(
                        &child(&child(&checkpoint_path, "runtime_launch"), "identity"),
                        "devices",
                    ),
                    output,
                );
            }
        }
        collect_require_idle_arrays(
            require_idle,
            &child(&checkpoint_path, "require_idle"),
            output,
        );
    }
    let processes_path = child(path, "processes");
    collect_order(&runtime.processes, &processes_path, process_key, output);
    if has_duplicate(
        runtime
            .processes
            .iter()
            .map(|process| (process.process_start_time_ticks.get(), process.process_id)),
    ) {
        output.push(Candidate::at(
            &processes_path,
            MalformedProblem::DuplicateIdentity,
        ));
    }
    let volumes_path = child(path, "volumes");
    collect_unique_order(
        &runtime.volumes,
        &volumes_path,
        |volume| volume.volume_id.as_str().as_bytes().to_vec(),
        output,
    );
    for (index, volume) in runtime.volumes.iter().enumerate() {
        collect_volume_arrays(volume, &indexed(&volumes_path, index), output);
    }
    collect_order(
        &runtime.mounts,
        &child(path, "mounts"),
        |mount| {
            vec![
                bytes(mount.volume_id.as_str()),
                bytes(mount.mount_path.as_str()),
                bytes(mount.source_path.as_str()),
                bytes(mount.guest_device.serial.as_str()),
                SortPart::Number(u64::from(mount.guest_device.slot)),
                SortPart::Number(match mount.access {
                    MountAccess::ReadWrite => 0,
                    MountAccess::ReadOnly => 1,
                }),
                canonical_part(mount),
            ]
        },
        output,
    );
    if has_duplicate(
        runtime
            .mounts
            .iter()
            .map(|mount| (mount.mount_path.as_str(), mount.source_path.as_str())),
    ) {
        output.push(Candidate::at(
            &child(path, "mounts"),
            MalformedProblem::DuplicateIdentity,
        ));
    }
    let networks_path = child(path, "networks");
    collect_order(
        &runtime.networks,
        &networks_path,
        |network| {
            vec![
                bytes(network.network_id.as_str()),
                bytes(network.tap_name.as_str()),
                bytes(network.guest_mac.as_str()),
                bytes(network.guest_ipv4.as_str()),
                bytes(network.gateway_ipv4.as_str()),
                canonical_part(network),
            ]
        },
        output,
    );
    if has_duplicate(runtime.networks.iter().map(|network| &network.tap_name)) {
        output.push(Candidate::at(
            &networks_path,
            MalformedProblem::DuplicateIdentity,
        ));
    }
    if let WarmSnapshotEvidence::Present { source_heads, .. } = &runtime.warm_snapshot {
        collect_unique_order(
            source_heads,
            &child(&child(path, "warm_snapshot"), "source_heads"),
            |head| head.volume_id.as_str().as_bytes().to_vec(),
            output,
        );
    }
    collect_order(&runtime.routes, &child(path, "routes"), route_key, output);
    if has_duplicate(runtime.routes.iter().map(|route| {
        (
            canonical_item(&route.binding),
            match route.gate {
                RouteGateState::Active => 0,
                RouteGateState::Closed => 1,
            },
            route.active_guards,
            route.cancellation_pending,
        )
    })) {
        output.push(Candidate::at(
            &child(path, "routes"),
            MalformedProblem::DuplicateIdentity,
        ));
    }
    let conditions_path = child(path, "conditions");
    collect_order(
        &runtime.conditions,
        &conditions_path,
        |condition| {
            let (kind, reason) = condition_ranks(condition);
            vec![
                SortPart::Number(kind),
                SortPart::Number(reason),
                canonical_part(condition),
            ]
        },
        output,
    );
    for (index, condition) in runtime.conditions.iter().enumerate() {
        collect_condition_arrays(condition, &indexed(&conditions_path, index), output);
    }
}

fn route_key(route: &ObservedRouteGate) -> Vec<SortPart> {
    vec![
        bytes(route.binding.endpoint_id.as_str()),
        SortPart::Number(route.binding.route_epoch.get()),
        bytes(route.binding.workspace_id.as_str()),
        bytes(route.binding.cat_id.as_str()),
        bytes(route.binding.node_id.as_str()),
        bytes(route.binding.runtime_incarnation.as_str()),
        SortPart::Number(match route.gate {
            RouteGateState::Active => 0,
            RouteGateState::Closed => 1,
        }),
        canonical_part(route),
    ]
}

fn child(path: &[PathSegment], key: &str) -> Vec<PathSegment> {
    let mut result = path.to_vec();
    result.push(PathSegment::Key(key.to_owned()));
    result
}

fn residue_key(residue: &NodeResidue) -> Vec<SortPart> {
    let mut key = match residue {
        NodeResidue::Process {
            process_start_time_ticks,
            process_id,
            executable_path,
            ..
        } => vec![
            SortPart::Number(0),
            SortPart::Number(process_start_time_ticks.get()),
            SortPart::Number(u64::from(*process_id)),
            bytes(executable_path.as_str()),
        ],
        NodeResidue::SystemdScope {
            scope_id,
            cgroup_path,
            ..
        } => vec![
            SortPart::Number(1),
            bytes(scope_id.as_str()),
            bytes(cgroup_path.as_str()),
        ],
        NodeResidue::ControlSocket { socket_path, .. } => {
            vec![SortPart::Number(2), bytes(socket_path.as_str())]
        }
        NodeResidue::CheckpointFile {
            checkpoint_path, ..
        } => vec![SortPart::Number(3), bytes(checkpoint_path.as_str())],
        NodeResidue::KernelNbd { device_path, .. } => {
            vec![SortPart::Number(4), bytes(device_path.as_str())]
        }
        NodeResidue::VhostUserBlk { socket_path, .. } => {
            vec![SortPart::Number(5), bytes(socket_path.as_str())]
        }
        NodeResidue::NetworkTap { tap_name, .. } => {
            vec![SortPart::Number(6), bytes(tap_name.as_str())]
        }
        NodeResidue::DataDirectory { data_directory, .. } => {
            vec![SortPart::Number(7), bytes(data_directory.as_str())]
        }
        NodeResidue::Mount {
            source_path,
            mount_path,
            ..
        } => vec![
            SortPart::Number(8),
            bytes(mount_path.as_str()),
            bytes(source_path.as_str()),
        ],
        NodeResidue::WarmSnapshot { path, .. } => {
            vec![SortPart::Number(9), bytes(path.as_str())]
        }
        NodeResidue::RouteGate { binding, .. } => {
            vec![SortPart::Number(10), canonical_part(binding)]
        }
    };
    key.push(canonical_part(residue));
    key
}

fn collect_checkpoint_arrays(checkpoint: &RuntimeCheckpoint) -> Vec<Candidate> {
    let mut output = Vec::new();
    collect_step_arrays(&checkpoint.step, &path(&["step"]), &mut output);
    if let RuntimeLaunch::Present(identity) = &checkpoint.runtime_launch {
        if checkpoint.step.start_runtime_launch_identity().as_ref() != Some(identity.as_ref()) {
            collect_prepared_device_arrays(
                &identity.devices,
                &path(&["runtime_launch", "identity", "devices"]),
                &mut output,
            );
        }
    }
    collect_require_idle_arrays(
        &checkpoint.require_idle,
        &path(&["require_idle"]),
        &mut output,
    );
    collect_order(
        &checkpoint.processes,
        &path(&["processes"]),
        process_key,
        &mut output,
    );
    if has_duplicate(
        checkpoint
            .processes
            .iter()
            .map(|process| (process.process_start_time_ticks.get(), process.process_id)),
    ) {
        output.push(Candidate::at(
            &path(&["processes"]),
            MalformedProblem::DuplicateIdentity,
        ));
    }
    collect_unique_order(
        &checkpoint.volumes,
        &path(&["volumes"]),
        |volume| volume.volume_id.as_str().as_bytes().to_vec(),
        &mut output,
    );
    for (index, volume) in checkpoint.volumes.iter().enumerate() {
        collect_volume_arrays(volume, &indexed(&path(&["volumes"]), index), &mut output);
    }
    collect_order(
        &checkpoint.mounts,
        &path(&["mounts"]),
        |mount| {
            vec![
                bytes(mount.volume_id.as_str()),
                bytes(mount.mount_path.as_str()),
                bytes(mount.source_path.as_str()),
                bytes(mount.guest_device.serial.as_str()),
                SortPart::Number(u64::from(mount.guest_device.slot)),
                SortPart::Number(match mount.access {
                    MountAccess::ReadWrite => 0,
                    MountAccess::ReadOnly => 1,
                }),
                canonical_part(mount),
            ]
        },
        &mut output,
    );
    if has_duplicate(
        checkpoint
            .mounts
            .iter()
            .map(|mount| (mount.mount_path.as_str(), mount.source_path.as_str())),
    ) {
        output.push(Candidate::at(
            &path(&["mounts"]),
            MalformedProblem::DuplicateIdentity,
        ));
    }
    collect_order(
        &checkpoint.networks,
        &path(&["networks"]),
        |network| {
            vec![
                bytes(network.network_id.as_str()),
                bytes(network.tap_name.as_str()),
                bytes(network.guest_mac.as_str()),
                bytes(network.guest_ipv4.as_str()),
                bytes(network.gateway_ipv4.as_str()),
                canonical_part(network),
            ]
        },
        &mut output,
    );
    if has_duplicate(checkpoint.networks.iter().map(|network| &network.tap_name)) {
        output.push(Candidate::at(
            &path(&["networks"]),
            MalformedProblem::DuplicateIdentity,
        ));
    }
    if let WarmSnapshotEvidence::Present { source_heads, .. } = &checkpoint.warm_snapshot {
        collect_unique_order(
            source_heads,
            &path(&["warm_snapshot", "source_heads"]),
            |head| head.volume_id.as_str().as_bytes().to_vec(),
            &mut output,
        );
    }
    collect_unique_order(
        &checkpoint.route_gates,
        &path(&["route_gates"]),
        |route| route.binding.endpoint_id.as_str().as_bytes().to_vec(),
        &mut output,
    );
    output
}

fn collect_cleanup_cross(
    cleanup: &CleanupRelease,
    path: &[PathSegment],
    checkpoint_file_required: bool,
    output: &mut Vec<Candidate>,
) {
    if cleanup.desired_read_position.get() < cleanup.inventory_read_position.get() {
        output.push(Candidate::at(path, MalformedProblem::InvalidValue));
    }
    let is_volume = matches!(cleanup.target, CleanupTarget::Volume { .. });
    if is_volume != cleanup.volume_release.is_some() {
        output.push(Candidate::at(path, MalformedProblem::InvalidValue));
    }
    if let Some(release) = &cleanup.volume_release {
        if !matches!(
            release.disposition,
            VolumeDisposition::Retain | VolumeDisposition::DetachRetained
        ) {
            output.push(Candidate::at(path, MalformedProblem::InvalidValue));
        }
    }
    let is_checkpoint_file = matches!(cleanup.target, CleanupTarget::CheckpointFile { .. });
    if checkpoint_file_required != is_checkpoint_file {
        output.push(Candidate::at(path, MalformedProblem::InvalidValue));
    }
}

fn collect_prepared_device_cross(
    expected_head: &RemoteHead,
    ownership_token: &RandomId128,
    serving_authority: &ServingAuthorityProvenance,
    serving_process: &ServingBlockdIdentity,
    frontend: &PrepareDeviceFrontend,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    let expected_head_path = child(path, "expected_head");
    collect_remote_head_cross(expected_head, &expected_head_path, output);
    let (authorization_path, requires_blank_head) = match serving_authority {
        ServingAuthorityProvenance::AfterRootProvision { handoff } => (&handoff.record.path, false),
        ServingAuthorityProvenance::DirectAuthorizedAttachment {
            authorization,
            purpose,
        } => (
            &authorization.path,
            matches!(
                purpose,
                DirectAuthorizedAttachmentPurpose::PersistentUninitialized
            ),
        ),
    };
    if (expected_head.generation.get() == 0) != requires_blank_head {
        output.push(Candidate::at(
            &expected_head_path,
            MalformedProblem::InvalidValue,
        ));
    }
    if ownership_token == &serving_process.process_identity_token {
        output.push(Candidate::field(
            path,
            "ownership_token",
            MalformedProblem::InvalidValue,
        ));
    }
    let frontend_path = child(path, "frontend");
    let (frontend_socket_path, device_path, duplicate_frontend_path, queue_size) = match frontend {
        PrepareDeviceFrontend::KernelNbd {
            listener_socket_path,
            device_path,
            ..
        } => (
            listener_socket_path,
            Some(device_path),
            listener_socket_path == device_path,
            None,
        ),
        PrepareDeviceFrontend::VhostUserBlk {
            socket_path,
            queue_size,
            ..
        } => (socket_path, None, false, Some(*queue_size)),
    };
    if duplicate_frontend_path
        || frontend_socket_path == &serving_process.control_socket_path
        || frontend_socket_path == &serving_process.data_directory
        || frontend_socket_path == &serving_process.executable_path
        || frontend_socket_path == authorization_path
        || device_path.is_some_and(|device_path| {
            device_path == &serving_process.control_socket_path
                || device_path == &serving_process.data_directory
                || device_path == &serving_process.executable_path
                || device_path == authorization_path
        })
    {
        output.push(Candidate::at(
            &frontend_path,
            MalformedProblem::InvalidValue,
        ));
    }
    if queue_size.is_some_and(|queue_size| !queue_size.is_power_of_two()) {
        output.push(Candidate::field(
            &frontend_path,
            "queue_size",
            MalformedProblem::InvalidValue,
        ));
    }
    if authorization_path == &serving_process.control_socket_path
        || authorization_path == &serving_process.data_directory
        || authorization_path == &serving_process.executable_path
    {
        output.push(Candidate::at(
            &child(path, "serving_authority"),
            MalformedProblem::InvalidValue,
        ));
    }
    if serving_process.control_socket_path == serving_process.data_directory
        || serving_process.control_socket_path == serving_process.executable_path
        || serving_process.data_directory == serving_process.executable_path
    {
        output.push(Candidate::at(
            &child(path, "serving_process"),
            MalformedProblem::InvalidValue,
        ));
    }
}

fn collect_device_kind_authority_cross(
    disk_kind: DiskKind,
    serving_authority: &ServingAuthorityProvenance,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    let authority_matches_disk_kind = matches!(
        (disk_kind, serving_authority),
        (
            DiskKind::Root,
            ServingAuthorityProvenance::AfterRootProvision { .. }
        ) | (
            DiskKind::Root,
            ServingAuthorityProvenance::DirectAuthorizedAttachment {
                purpose: DirectAuthorizedAttachmentPurpose::ExistingRoot,
                ..
            }
        ) | (
            DiskKind::Persistent,
            ServingAuthorityProvenance::DirectAuthorizedAttachment {
                purpose: DirectAuthorizedAttachmentPurpose::PersistentInitialized
                    | DirectAuthorizedAttachmentPurpose::PersistentUninitialized,
                ..
            }
        )
    );
    if !authority_matches_disk_kind {
        output.push(Candidate::at(
            &child(path, "serving_authority"),
            MalformedProblem::InvalidValue,
        ));
    }
}

fn collect_reconcile_step_cross(
    step: &ReconcileStep,
    path: &[PathSegment],
    checkpoint_file_allowed: bool,
    output: &mut Vec<Candidate>,
) {
    match step {
        ReconcileStep::PrepareDevice { devices } => {
            collect_prepared_devices_cross(devices, &child(path, "devices"), None, output)
        }
        ReconcileStep::PrepareNetwork { network, devices } => {
            let network_path = child(path, "network");
            collect_network_config_cross(
                &network.network_config,
                &child(&network_path, "network_config"),
                output,
            );
            if !valid_runtime_tap_name(&network.tap_name) {
                output.push(Candidate::field(
                    &network_path,
                    "tap_name",
                    MalformedProblem::InvalidValue,
                ));
            }
            collect_prepared_devices_cross(devices, &child(path, "devices"), None, output);
            let planned_tokens = std::iter::once(&network.ownership_token).chain(
                devices.iter().flat_map(|device| {
                    [
                        &device.ownership_token,
                        &device.serving_process.process_identity_token,
                    ]
                }),
            );
            if has_duplicate(planned_tokens) {
                output.push(Candidate::field(
                    &network_path,
                    "ownership_token",
                    MalformedProblem::InvalidValue,
                ));
            }
        }
        ReconcileStep::StartRuntime {
            runtime_incarnation,
            scope_id,
            launcher_executable,
            boot,
            process_identity_token,
            vcpus,
            memory_bytes,
            guest_config_digest: expected_guest_config_digest,
            api_socket_path,
            vsock_socket_path,
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            network,
            devices,
            ..
        } => {
            let network_path = child(path, "network");
            collect_network_config_cross(
                &network.network_config,
                &child(&network_path, "network_config"),
                output,
            );
            if !valid_runtime_tap_name(&network.tap_name) {
                output.push(Candidate::field(
                    &network_path,
                    "tap_name",
                    MalformedProblem::InvalidValue,
                ));
            }
            if !valid_vmm_service_id(scope_id, runtime_incarnation) {
                output.push(Candidate::field(
                    path,
                    "scope_id",
                    MalformedProblem::InvalidValue,
                ));
            }
            if process_identity_token == runtime_incarnation
                || process_identity_token == &network.ownership_token
            {
                output.push(Candidate::field(
                    path,
                    "process_identity_token",
                    MalformedProblem::InvalidValue,
                ));
            }

            if *memory_bytes < 128 * MEBIBYTE || *memory_bytes % MEBIBYTE != 0 {
                output.push(Candidate::field(
                    path,
                    "memory_bytes",
                    MalformedProblem::InvalidValue,
                ));
            }
            if vsock_socket_path.as_str().contains(',') {
                output.push(Candidate::field(
                    path,
                    "vsock_socket_path",
                    MalformedProblem::InvalidValue,
                ));
            }
            if !launch_file_parents_are_equal_or_disjoint(&[
                memory_file_path,
                serial_log_path,
                vmm_log_path,
            ]) {
                output.push(Candidate::at(path, MalformedProblem::InvalidValue));
            }

            let profile = GuestRuntimeProfileReceipt {
                version: ContractVersion::V1,
                kernel_digest: boot.kernel.content_sha256.clone(),
                initramfs_digest: boot
                    .initramfs
                    .as_ref()
                    .map(|artifact| artifact.content_sha256.clone()),
                kernel_cmdline: boot.kernel_cmdline.clone(),
                guest_agent_protocol_version: ContractVersion::V1,
            };
            if guest_config_digest(&profile).as_ref() != Ok(expected_guest_config_digest) {
                output.push(Candidate::field(
                    path,
                    "guest_config_digest",
                    MalformedProblem::InvalidValue,
                ));
            }

            let launch_paths = [
                &launcher_executable.path,
                &boot.vmm_executable.path,
                &boot.kernel.path,
                api_socket_path,
                vsock_socket_path,
                memory_file_path,
                serial_log_path,
                vmm_log_path,
            ];
            let initramfs_path = boot.initramfs.as_ref().map(|artifact| &artifact.path);
            let prepared_paths = devices
                .iter()
                .flat_map(prepared_device_identity_paths)
                .flatten();
            let launch_aliases_serving_executable = launch_paths
                .iter()
                .copied()
                .chain(initramfs_path)
                .any(|launch_path| {
                    devices
                        .iter()
                        .any(|device| launch_path == &device.serving_process.executable_path)
                });
            if has_duplicate(
                launch_paths
                    .iter()
                    .copied()
                    .chain(initramfs_path)
                    .chain(prepared_paths),
            ) || launch_aliases_serving_executable
            {
                output.push(Candidate::at(path, MalformedProblem::InvalidValue));
            }

            let devices_path = child(path, "devices");
            collect_prepared_devices_cross(devices, &devices_path, Some(*vcpus), output);

            let planned_tokens = std::iter::once(runtime_incarnation)
                .chain(std::iter::once(process_identity_token))
                .chain(std::iter::once(&network.ownership_token))
                .chain(devices.iter().flat_map(|device| {
                    [
                        &device.ownership_token,
                        &device.serving_process.process_identity_token,
                    ]
                }));
            if has_duplicate(planned_tokens)
                || devices
                    .iter()
                    .any(|device| device.serving_process.scope_id == *scope_id)
            {
                output.push(Candidate::at(path, MalformedProblem::InvalidValue));
            }
        }
        ReconcileStep::FormatFilesystem { filesystem } => {
            collect_persistent_filesystem_binding_cross(filesystem, path, true, output);
        }
        ReconcileStep::CommitInitialized {
            filesystem,
            new_remote_head,
        } => {
            collect_persistent_filesystem_binding_cross(filesystem, path, true, output);
            collect_remote_head_cross(new_remote_head, &child(path, "new_remote_head"), output);
            if new_remote_head.generation.get() == 0 {
                output.push(Candidate::field(
                    path,
                    "new_remote_head",
                    MalformedProblem::InvalidValue,
                ));
            }
        }
        ReconcileStep::DrainInitialization {
            filesystem,
            local_generation,
            remote_generation,
        } => {
            collect_persistent_filesystem_binding_cross(filesystem, path, true, output);
            if local_generation.get() < remote_generation.get() {
                output.push(Candidate::at(path, MalformedProblem::InvalidValue));
            }
        }
        ReconcileStep::MountFilesystem {
            filesystem,
            expected_head,
        } => {
            collect_persistent_filesystem_binding_cross(filesystem, path, false, output);
            collect_remote_head_cross(expected_head, &child(path, "expected_head"), output);
            if expected_head.generation.get() == 0 {
                output.push(Candidate::field(
                    path,
                    "expected_head",
                    MalformedProblem::InvalidValue,
                ));
            }
        }
        ReconcileStep::ProvisionRootImage {
            expected_blank_head,
            expected_provisioned_head,
            ..
        } => {
            collect_remote_head_cross(
                expected_blank_head,
                &child(path, "expected_blank_head"),
                output,
            );
            collect_remote_head_cross(
                expected_provisioned_head,
                &child(path, "expected_provisioned_head"),
                output,
            );
        }
        ReconcileStep::SnapshotWarmRuntime { source_heads, .. } => {
            collect_volume_heads_cross(source_heads, &child(path, "source_heads"), output);
        }
        ReconcileStep::CleanupRelease { cleanup } => {
            collect_cleanup_cross(
                cleanup,
                &child(path, "cleanup"),
                checkpoint_file_allowed,
                output,
            );
        }
        ReconcileStep::DrainPublish {
            local_generation,
            remote_generation,
            ..
        } if local_generation.get() < remote_generation.get() => {
            output.push(Candidate::at(path, MalformedProblem::InvalidValue));
        }
        _ => {}
    }
}

fn collect_persistent_filesystem_binding_cross(
    filesystem: &PersistentFilesystemBinding,
    step_path: &[PathSegment],
    initialize_required: bool,
    output: &mut Vec<Candidate>,
) {
    let path = child(step_path, "filesystem");
    if filesystem.mount_path.as_str() == "/" {
        output.push(Candidate::field(
            &path,
            "mount_path",
            MalformedProblem::InvalidValue,
        ));
    }
    match &filesystem.initialization {
        FilesystemInitialization::Initialize {
            initialization_token,
            expected_blank_head,
        } => {
            let initialization_path = child(&path, "initialization");
            collect_remote_head_cross(
                expected_blank_head,
                &child(&initialization_path, "expected_blank_head"),
                output,
            );
            if expected_blank_head.generation.get() != 0 {
                output.push(Candidate::field(
                    &initialization_path,
                    "expected_blank_head",
                    MalformedProblem::InvalidValue,
                ));
            }
            if initialization_token == &filesystem.filesystem_uuid {
                output.push(Candidate::at(
                    &initialization_path,
                    MalformedProblem::InvalidValue,
                ));
            }
        }
        FilesystemInitialization::Existing if initialize_required => {
            output.push(Candidate::field(
                &path,
                "initialization",
                MalformedProblem::InvalidValue,
            ));
        }
        FilesystemInitialization::Existing => {}
    }
}

fn valid_runtime_tap_name(tap_name: &Id) -> bool {
    let value = tap_name.as_str();
    !matches!(value, "." | "..")
        && value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn valid_vmm_service_id(scope_id: &Id, runtime_incarnation: &RandomId128) -> bool {
    scope_id
        .as_str()
        .strip_prefix("cats-vmm-")
        .and_then(|body| body.strip_suffix(".service"))
        == Some(runtime_incarnation.as_str())
}

fn collect_volume_heads_cross(
    heads: &[VolumeHeadEvidence],
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    for (index, evidence) in heads.iter().enumerate() {
        collect_remote_head_cross(
            &evidence.head,
            &child(&indexed(path, index), "head"),
            output,
        );
    }
}

fn collect_remote_head_cross(head: &RemoteHead, path: &[PathSegment], output: &mut Vec<Candidate>) {
    let has_hash = head.root_hash.is_some();
    let has_object_id = head.root_object_id.is_some();
    let valid = if head.generation.get() == 0 {
        !has_hash && !has_object_id
    } else {
        has_hash && has_object_id
    };
    if !valid {
        output.push(Candidate::at(path, MalformedProblem::InvalidValue));
    }
}

fn collect_warm_snapshot_cross(
    snapshot: &WarmSnapshotEvidence,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    if let WarmSnapshotEvidence::Present { source_heads, .. } = snapshot {
        collect_volume_heads_cross(source_heads, &child(path, "source_heads"), output);
    }
}

fn incarnation_matches_state(
    state: Option<StableState>,
    incarnation: Option<&RandomId128>,
) -> bool {
    match state {
        Some(StableState::Running | StableState::Suspended) => incarnation.is_some(),
        Some(StableState::Warm | StableState::Cold | StableState::Deleted) => incarnation.is_none(),
        None => true,
    }
}

fn target_matches_incarnation(target: RuntimeTarget, incarnation: Option<&RandomId128>) -> bool {
    match target {
        RuntimeTarget::Running | RuntimeTarget::Suspended => incarnation.is_some(),
        RuntimeTarget::Warm | RuntimeTarget::Cold | RuntimeTarget::Deleted => incarnation.is_none(),
    }
}

fn collect_physical_cross(
    processes: &[ProcessEvidence],
    volumes: &[ObservedVolume],
    base: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    let processes_path = child(base, "processes");
    for (index, process) in processes.iter().enumerate() {
        let valid_shape = match (&process.role, &process.control_handshake) {
            (ProcessRole::Vmm { .. }, ControlHandshakeEvidence::Verified) => {
                process.observed_vm_shape.is_some()
            }
            (ProcessRole::Vmm { .. }, _) | (ProcessRole::Blockd { .. }, _) => {
                process.observed_vm_shape.is_none()
            }
        };
        if !valid_shape {
            output.push(Candidate::at(
                &indexed(&processes_path, index),
                MalformedProblem::InvalidValue,
            ));
        }
    }
    let volumes_path = child(base, "volumes");
    for (index, volume) in volumes.iter().enumerate() {
        let volume_path = indexed(&volumes_path, index);
        let identities_valid = match volume.disk_kind {
            ObservedDiskKind::Unknown => {
                volume.volume_intent_id.is_none() && volume.disk_id.is_none()
            }
            ObservedDiskKind::Root | ObservedDiskKind::Persistent => {
                volume.volume_intent_id.is_some() && volume.disk_id.is_some()
            }
        };
        if !identities_valid {
            output.push(Candidate::at(&volume_path, MalformedProblem::InvalidValue));
        }
        match &volume.authority {
            VolumeAuthorityEvidence::Unowned { head, .. }
            | VolumeAuthorityEvidence::Owned { head, .. }
            | VolumeAuthorityEvidence::Deleting { head, .. } => {
                collect_remote_head_cross(
                    head,
                    &child(&child(&volume_path, "authority"), "head"),
                    output,
                );
            }
            VolumeAuthorityEvidence::Unavailable | VolumeAuthorityEvidence::Absent => {}
        }
        for (lineage_index, lineage) in volume.local_lineages.iter().enumerate() {
            if lineage.local_durable_generation.get() < lineage.remote_durable_generation.get() {
                output.push(Candidate::at(
                    &indexed(&child(&volume_path, "local_lineages"), lineage_index),
                    MalformedProblem::InvalidValue,
                ));
            }
        }
    }
}

fn collect_condition_cross(
    condition: &Condition,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    let reason_path = child(path, "reason");
    match condition {
        Condition::Progressing {
            reason: ProgressingReason::ReconcileStep { step },
        } => collect_reconcile_step_cross(step, &child(&reason_path, "step"), false, output),
        Condition::Blocked { reason } => match reason {
            BlockedReason::IncompleteInventory {
                unavailable_sources,
            } if unavailable_sources.is_empty() => {
                output.push(Candidate::at(&reason_path, MalformedProblem::InvalidValue));
            }
            BlockedReason::ActiveGuards {
                platform_guards,
                endpoint_guards,
            } if *platform_guards == 0 && endpoint_guards.is_empty() => {
                output.push(Candidate::at(&reason_path, MalformedProblem::InvalidValue));
            }
            BlockedReason::VolumeAuthorityUnavailable { volume_ids } if volume_ids.is_empty() => {
                output.push(Candidate::at(&reason_path, MalformedProblem::InvalidValue));
            }
            BlockedReason::RemoteDurabilityLag {
                local_generation,
                remote_generation,
                ..
            } if local_generation.get() <= remote_generation.get() => {
                output.push(Candidate::at(&reason_path, MalformedProblem::InvalidValue));
            }
            BlockedReason::KeyRingUnavailable {
                loaded_version,
                loaded_digest,
                ..
            } if loaded_version.is_some() != loaded_digest.is_some() => {
                output.push(Candidate::at(&reason_path, MalformedProblem::InvalidValue));
            }
            _ => {}
        },
        Condition::Degraded {
            reason: DegradedReason::SourceUnavailable { sources, .. },
        } if sources.is_empty() => {
            output.push(Candidate::at(&reason_path, MalformedProblem::InvalidValue));
        }
        Condition::Quarantined { reason } => {
            collect_quarantine_cross(reason, &reason_path, output);
        }
        Condition::DataLossPossible {
            reason:
                DataLossReason::RemoteTailUnavailable {
                    local_generation,
                    remote_generation,
                    ..
                },
        } if local_generation.get() <= remote_generation.get() => {
            output.push(Candidate::at(&reason_path, MalformedProblem::InvalidValue));
        }
        _ => {}
    }
}

fn collect_quarantine_cross(
    reason: &QuarantineReason,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    let valid = match reason {
        QuarantineReason::RuntimeIdentityConflict {
            expected_incarnation,
            observed_incarnations,
        } => {
            !observed_incarnations.is_empty()
                && observed_incarnations
                    .iter()
                    .any(|observed| observed != expected_incarnation)
        }
        QuarantineReason::DuplicateRuntime {
            observed_incarnations,
        } => observed_incarnations.len() >= 2,
        QuarantineReason::ProcessIdentityConflict { process_ids, .. } => process_ids.len() >= 2,
        QuarantineReason::DuplicateWriter {
            observed_attachments,
            ..
        } => observed_attachments.len() >= 2,
        QuarantineReason::DuplicateDevice {
            observed_device_count,
            ..
        } => observed_device_count.get() >= 2,
        QuarantineReason::DuplicateMount {
            observed_instance_count,
            ..
        }
        | QuarantineReason::DuplicateRoute {
            observed_instance_count,
            ..
        } => observed_instance_count.get() >= 2,
        QuarantineReason::DuplicateNetwork {
            observed_tap_count, ..
        } => observed_tap_count.get() >= 2,
        QuarantineReason::InvalidOwnershipToken { evidence, .. } => {
            !matches!(evidence, OwnershipTokenEvidence::Valid { .. })
        }
        QuarantineReason::UnattributedNodeResidue { residue } => {
            collect_node_residue_cross(residue, &child(path, "residue"), output);
            true
        }
        _ => true,
    };
    if !valid {
        output.push(Candidate::at(path, MalformedProblem::InvalidValue));
    }
}

fn collect_runtime_cross(
    runtime: &ObservedRuntimeStatus,
    complete_inventory: bool,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    collect_reconcile_step_cross(&runtime.step, &child(path, "step"), false, output);
    collect_runtime_resource_cross(runtime, path, output);
    collect_physical_cross(&runtime.processes, &runtime.volumes, path, output);
    collect_warm_snapshot_cross(
        &runtime.warm_snapshot,
        &child(path, "warm_snapshot"),
        output,
    );
    if !incarnation_matches_state(runtime.stable_state, runtime.runtime_incarnation.as_ref()) {
        output.push(Candidate::at(path, MalformedProblem::InvalidValue));
    }
    collect_applied_desired_cross(complete_inventory, runtime, path, output);
    if runtime
        .conditions
        .iter()
        .filter(|condition| matches!(condition, Condition::Ready { .. }))
        .count()
        > 1
    {
        output.push(Candidate::at(
            &child(path, "conditions"),
            MalformedProblem::DuplicateIdentity,
        ));
    }
    match &runtime.checkpoint {
        CheckpointEvidence::Missing { .. } | CheckpointEvidence::Corrupt { .. }
            if !matches!(
                runtime.step,
                ReconcileStep::InspectInventory { .. } | ReconcileStep::Quarantined
            ) =>
        {
            output.push(Candidate::at(path, MalformedProblem::InvalidValue));
        }
        CheckpointEvidence::Valid {
            cat_id,
            step,
            runtime_incarnation,
            runtime_launch,
            stable_state,
            ..
        } => {
            if cat_id != &runtime.cat_id || step.as_ref() != &runtime.step {
                output.push(Candidate::at(path, MalformedProblem::InvalidValue));
            }
            if !incarnation_matches_state(*stable_state, runtime_incarnation.as_ref()) {
                output.push(Candidate::at(
                    &child(path, "checkpoint"),
                    MalformedProblem::InvalidValue,
                ));
            }
            collect_reconcile_step_cross(
                step,
                &child(&child(path, "checkpoint"), "step"),
                false,
                output,
            );
            collect_runtime_launch_cross(
                runtime_incarnation.as_ref(),
                runtime_launch,
                step,
                &child(path, "checkpoint"),
                output,
            );
        }
        _ => {}
    }
    for (index, condition) in runtime.conditions.iter().enumerate() {
        let condition_path = indexed(&child(path, "conditions"), index);
        collect_condition_cross(condition, &condition_path, output);
        collect_runtime_condition_cross(runtime, condition, path, output);
    }
}

fn collect_applied_desired_cross(
    complete_inventory: bool,
    runtime: &ObservedRuntimeStatus,
    runtime_path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    if runtime.applied_desired.is_some() {
        return;
    }
    if !complete_inventory {
        output.push(Candidate::at(&[], MalformedProblem::InvalidValue));
    }
    if runtime
        .conditions
        .iter()
        .any(|condition| matches!(condition, Condition::Ready { .. }))
    {
        output.push(Candidate::at(runtime_path, MalformedProblem::InvalidValue));
    }
}

fn collect_runtime_condition_cross(
    runtime: &ObservedRuntimeStatus,
    condition: &Condition,
    runtime_path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    let valid = match condition {
        Condition::Ready {
            reason: ReadyReason::PostconditionSatisfied { target },
        } => {
            let stable_target = runtime.stable_state.map(|state| match state {
                StableState::Running => RuntimeTarget::Running,
                StableState::Suspended => RuntimeTarget::Suspended,
                StableState::Warm => RuntimeTarget::Warm,
                StableState::Cold => RuntimeTarget::Cold,
                StableState::Deleted => RuntimeTarget::Deleted,
            });
            stable_target == Some(*target)
                && runtime
                    .applied_desired
                    .as_ref()
                    .is_some_and(|applied| applied.target == *target)
        }
        Condition::Quarantined {
            reason:
                QuarantineReason::DuplicateDevice {
                    volume_id,
                    observed_device_count,
                },
        } => runtime
            .volumes
            .iter()
            .find(|volume| volume.volume_id == *volume_id)
            .is_some_and(|volume| observed_device_count.get() == volume.devices.len() as u64),
        Condition::Quarantined {
            reason:
                QuarantineReason::DuplicateMount {
                    volume_id,
                    mount_path,
                    observed_instance_count,
                },
        } => sum_matching(
            runtime
                .mounts
                .iter()
                .filter(|mount| mount.volume_id == *volume_id && mount.mount_path == *mount_path)
                .map(|mount| mount.instance_count),
        )
        .is_some_and(|count| count == observed_instance_count.get()),
        Condition::Quarantined {
            reason:
                QuarantineReason::DuplicateNetwork {
                    network_id,
                    observed_tap_count,
                },
        } => {
            let count = runtime
                .networks
                .iter()
                .filter(|network| network.network_id == *network_id)
                .count() as u64;
            count == observed_tap_count.get()
        }
        Condition::Quarantined {
            reason:
                QuarantineReason::DuplicateRoute {
                    endpoint_id,
                    observed_instance_count,
                },
        } => sum_matching(
            runtime
                .routes
                .iter()
                .filter(|route| route.binding.endpoint_id == *endpoint_id)
                .map(|route| route.instance_count),
        )
        .is_some_and(|count| count == observed_instance_count.get()),
        _ => true,
    };
    if !valid {
        output.push(Candidate::at(runtime_path, MalformedProblem::InvalidValue));
    }
}

fn sum_matching(values: impl IntoIterator<Item = u64>) -> Option<u64> {
    values
        .into_iter()
        .try_fold(0_u64, |total, value| total.checked_add(value))
        .filter(|total| *total <= MAX_WIRE_INTEGER)
}

fn collect_residue_cross(
    residue: &[NodeResidue],
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    for (index, item) in residue.iter().enumerate() {
        collect_node_residue_cross(item, &indexed(path, index), output);
    }
}

fn collect_node_residue_cross(
    residue: &NodeResidue,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    if let NodeResidue::DataDirectory { lineage, .. } = residue {
        collect_residue_lineage_cross(lineage, &child(path, "lineage"), output);
    }
}

fn collect_residue_lineage_cross(
    lineage: &ResidueLineageEvidence,
    path: &[PathSegment],
    output: &mut Vec<Candidate>,
) {
    if let ResidueLineageEvidence::Readable {
        attachment_id_hint,
        attachment_epoch_hint,
        local_durable_generation,
        remote_durable_generation,
        ..
    } = lineage
    {
        if attachment_id_hint.is_some() != attachment_epoch_hint.is_some()
            || local_durable_generation.get() < remote_durable_generation.get()
        {
            output.push(Candidate::at(path, MalformedProblem::InvalidValue));
        }
    }
}

fn collect_inventory_collisions(observation: &NodeObservation, output: &mut Vec<Candidate>) {
    let mut identities: BTreeMap<(&'static str, String), Vec<Vec<PathSegment>>> = BTreeMap::new();
    for (runtime_index, runtime) in observation.runtimes.iter().enumerate() {
        let runtime_path = indexed(&path(&["runtimes"]), runtime_index);
        let mut runtime_scopes = BTreeSet::new();
        for (process_index, process) in runtime.processes.iter().enumerate() {
            let process_path = indexed(&child(&runtime_path, "processes"), process_index);
            add_identity(
                &mut identities,
                "process",
                format!(
                    "{}:{}",
                    process.process_start_time_ticks.get(),
                    process.process_id
                ),
                &process_path,
            );
            if runtime_scopes.insert(process.scope_id.as_str()) {
                add_identity(
                    &mut identities,
                    "scope",
                    process.scope_id.as_str().to_owned(),
                    &process_path,
                );
            }
            add_identity(
                &mut identities,
                "control_socket",
                process.control_socket_path.as_str().to_owned(),
                &process_path,
            );
        }
        for (volume_index, volume) in runtime.volumes.iter().enumerate() {
            let volume_path = indexed(&child(&runtime_path, "volumes"), volume_index);
            for (lineage_index, lineage) in volume.local_lineages.iter().enumerate() {
                add_identity(
                    &mut identities,
                    "data_directory",
                    lineage.data_directory.as_str().to_owned(),
                    &indexed(&child(&volume_path, "local_lineages"), lineage_index),
                );
            }
            for (device_index, device) in volume.devices.iter().enumerate() {
                let physical_path = match device {
                    ObservedDevice::KernelNbd { device_path, .. } => device_path,
                    ObservedDevice::VhostUserBlk { socket_path, .. } => socket_path,
                };
                add_identity(
                    &mut identities,
                    "block_frontend",
                    physical_path.as_str().to_owned(),
                    &indexed(&child(&volume_path, "devices"), device_index),
                );
            }
        }
        for (mount_index, mount) in runtime.mounts.iter().enumerate() {
            add_identity(
                &mut identities,
                "mount",
                mount_identity(&mount.mount_path, &mount.source_path),
                &indexed(&child(&runtime_path, "mounts"), mount_index),
            );
        }
        for (network_index, network) in runtime.networks.iter().enumerate() {
            add_identity(
                &mut identities,
                "network_tap",
                network.tap_name.as_str().to_owned(),
                &indexed(&child(&runtime_path, "networks"), network_index),
            );
        }
        if let WarmSnapshotEvidence::Present { path, .. } = &runtime.warm_snapshot {
            add_identity(
                &mut identities,
                "warm_snapshot",
                path.as_str().to_owned(),
                &child(&runtime_path, "warm_snapshot"),
            );
        }
        for (route_index, route) in runtime.routes.iter().enumerate() {
            add_identity(
                &mut identities,
                "route_gate",
                String::from_utf8(canonical_item(&route.binding))
                    .expect("canonical JSON is valid UTF-8"),
                &indexed(&child(&runtime_path, "routes"), route_index),
            );
        }
        let checkpoint_path = match &runtime.checkpoint {
            CheckpointEvidence::Missing { checkpoint_path }
            | CheckpointEvidence::Corrupt {
                checkpoint_path, ..
            }
            | CheckpointEvidence::Valid {
                checkpoint_path, ..
            } => checkpoint_path,
        };
        add_identity(
            &mut identities,
            "checkpoint",
            checkpoint_path.as_str().to_owned(),
            &child(&runtime_path, "checkpoint"),
        );
    }
    for (index, residue) in observation.residue.iter().enumerate() {
        let residue_path = indexed(&path(&["residue"]), index);
        match residue {
            NodeResidue::Process {
                process_start_time_ticks,
                process_id,
                ..
            } => add_identity(
                &mut identities,
                "process",
                format!("{}:{}", process_start_time_ticks.get(), process_id),
                &residue_path,
            ),
            NodeResidue::SystemdScope { scope_id, .. } => add_identity(
                &mut identities,
                "scope",
                scope_id.as_str().to_owned(),
                &residue_path,
            ),
            NodeResidue::ControlSocket { socket_path, .. } => add_identity(
                &mut identities,
                "control_socket",
                socket_path.as_str().to_owned(),
                &residue_path,
            ),
            NodeResidue::CheckpointFile {
                checkpoint_path, ..
            } => add_identity(
                &mut identities,
                "checkpoint",
                checkpoint_path.as_str().to_owned(),
                &residue_path,
            ),
            NodeResidue::KernelNbd { device_path, .. } => add_identity(
                &mut identities,
                "block_frontend",
                device_path.as_str().to_owned(),
                &residue_path,
            ),
            NodeResidue::VhostUserBlk { socket_path, .. } => add_identity(
                &mut identities,
                "block_frontend",
                socket_path.as_str().to_owned(),
                &residue_path,
            ),
            NodeResidue::NetworkTap { tap_name, .. } => add_identity(
                &mut identities,
                "network_tap",
                tap_name.as_str().to_owned(),
                &residue_path,
            ),
            NodeResidue::DataDirectory { data_directory, .. } => add_identity(
                &mut identities,
                "data_directory",
                data_directory.as_str().to_owned(),
                &residue_path,
            ),
            NodeResidue::Mount {
                source_path,
                mount_path,
                ..
            } => add_identity(
                &mut identities,
                "mount",
                mount_identity(mount_path, source_path),
                &residue_path,
            ),
            NodeResidue::WarmSnapshot { path, .. } => add_identity(
                &mut identities,
                "warm_snapshot",
                path.as_str().to_owned(),
                &residue_path,
            ),
            NodeResidue::RouteGate {
                binding: RouteBindingEvidence::Valid { binding },
                ..
            } => add_identity(
                &mut identities,
                "route_gate",
                String::from_utf8(canonical_item(binding)).expect("canonical JSON is valid UTF-8"),
                &residue_path,
            ),
            NodeResidue::RouteGate { .. } => {}
        }
    }
    for paths in identities.into_values().filter(|paths| paths.len() > 1) {
        output.push(Candidate::at(
            &lowest_common_path(&paths),
            MalformedProblem::DuplicateIdentity,
        ));
    }
}

fn mount_identity(mount_path: &HostPath, source_path: &HostPath) -> String {
    // HostPath excludes NUL, so this tuple encoding cannot alias two path pairs.
    format!("{}\0{}", mount_path.as_str(), source_path.as_str())
}

fn add_identity(
    identities: &mut BTreeMap<(&'static str, String), Vec<Vec<PathSegment>>>,
    kind: &'static str,
    identity: String,
    path: &[PathSegment],
) {
    identities
        .entry((kind, identity))
        .or_default()
        .push(path.to_vec());
}

fn lowest_common_path(paths: &[Vec<PathSegment>]) -> Vec<PathSegment> {
    let Some(first) = paths.first() else {
        return Vec::new();
    };
    let mut length = first.len();
    for path in &paths[1..] {
        length = length.min(path.len());
        let common = first[..length]
            .iter()
            .zip(&path[..length])
            .take_while(|(left, right)| left == right)
            .count();
        length = common;
    }
    first[..length].to_vec()
}
