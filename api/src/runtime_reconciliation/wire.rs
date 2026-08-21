use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::sync::LazyLock;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{de::DeserializeOwned, Serialize};

use super::canonical::value_bytes;
use super::types::*;

pub const NODE_IDENTITY_MAX_WIRE_BYTES: usize = 16_384;
pub const AGENT_REGISTRATION_ATTEMPT_MAX_WIRE_BYTES: usize = 16_384;
pub const AGENT_SESSION_MAX_WIRE_BYTES: usize = 16_384;
pub const GUEST_RUNTIME_PROFILE_RECEIPT_MAX_WIRE_BYTES: usize = 4_096;
pub const ADMISSION_INVENTORY_ATTESTATION_MAX_WIRE_BYTES: usize = 16_384;
pub const RUNTIME_SPINE_ERROR_MAX_WIRE_BYTES: usize = 20_480;
#[cfg(feature = "proposed-node-residue-reclamation")]
pub const RUNTIME_RESIDUE_AUTHORITY_REQUEST_MAX_WIRE_BYTES: usize = 16_384;
#[cfg(feature = "proposed-node-residue-reclamation")]
pub const RUNTIME_RESIDUE_AUTHORITY_SUCCESS_MAX_WIRE_BYTES: usize = 65_536;
pub const CONTRACT_ERROR_MAX_WIRE_BYTES: usize = 16_384;
pub const PROVISION_ROOT_IMAGE_REQUEST_MAX_WIRE_BYTES: usize = 4_096;
pub const PROVISION_ROOT_IMAGE_RESULT_MAX_WIRE_BYTES: usize = 4_096;
pub const PROVISION_ROOT_IMAGE_ERROR_MAX_WIRE_BYTES: usize = 4_096;
pub const NODE_PLACEMENT_POLICY_MAX_WIRE_BYTES: usize = 65_536;
pub const RUNTIME_NODE_AUTHORITY_APPLY_MAX_WIRE_BYTES: usize = 65_536;
pub const RUNTIME_NODE_AUTHORITY_APPLY_RESULT_MAX_WIRE_BYTES: usize = 16_384;
pub const RUNTIME_PROVISIONER_TRUST_BUNDLE_MAX_WIRE_BYTES: usize = 16_384;
pub const RUNTIME_PROVISIONER_ACTIVE_SET_MAX_WIRE_BYTES: usize = 16_384;

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
    AsciiText,
    JsonPointer,
    RandomId,
    Digest,
    NodeTransportTarget,
    Ipv4,
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
        StringRule::AsciiText => valid_ascii_text(value),
        StringRule::JsonPointer => valid_json_pointer(value),
        StringRule::RandomId => valid_random_id(value),
        StringRule::Digest => valid_digest(value),
        StringRule::NodeTransportTarget => valid_node_transport_target(value),
        StringRule::Ipv4 => valid_ipv4(value),
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

fn session_binding_schema() -> Schema {
    object(vec![
        field("node_id", id()),
        field("node_boot_id", random_id()),
        field("agent_instance_id", random_id()),
        field("agent_session_epoch", epoch()),
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

fn volume_transition_source_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("independent", vec![]),
            variant(
                "lifecycle",
                vec![
                    field("operation_id", id()),
                    field("request_fingerprint", digest()),
                ],
            ),
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
                    field("source", volume_transition_source_schema()),
                    field("request", normal_acquire_request_schema()),
                    field("result", normal_acquire_result_schema()),
                ],
            ),
            variant(
                "release",
                vec![
                    field("source", volume_transition_source_schema()),
                    field("request", release_request_schema()),
                    field("result", release_result_schema()),
                ],
            ),
            variant(
                "takeover",
                vec![
                    field("source", volume_transition_source_schema()),
                    field("authorization_id", id()),
                ],
            ),
            variant(
                "begin_delete",
                vec![
                    field("source", volume_transition_source_schema()),
                    field("request", begin_delete_request_schema()),
                    field("result", begin_delete_result_schema()),
                ],
            ),
            variant(
                "begin_disposable_delete",
                vec![
                    field("source", volume_transition_source_schema()),
                    field("authorization_id", id()),
                ],
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
        field("operation_id", id()),
        field("request_fingerprint", digest()),
        field("authorized_node_id", id()),
        field("host_fence_event_id", id()),
        field("interrupted_operation_id", id()),
        field("host_lost_result_digest", digest()),
        field("disk_id", id()),
        field("volume_id", id()),
        field("cat_id", id()),
        field("expected_attachment_id", id()),
        field("expected_epoch", wire_u64()),
        field("expected_head", remote_head_schema()),
        field("new_attachment_id", id()),
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
                "lifecycle_strong_stop",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("strong_stop_operation_id", id()),
                    field("strong_stop_receipt_digest", digest()),
                    field("execution_absence_proof_digest", digest()),
                    field("inventory_attestation_digest", digest()),
                ],
            ),
            variant(
                "host_fence_event",
                vec![
                    field("event_id", id()),
                    field("interrupted_operation_id", id()),
                    field("host_lost_result_digest", digest()),
                ],
            ),
        ],
    )
}

fn disposable_delete_authorization_fields() -> Vec<Field> {
    vec![
        field("authorization_id", id()),
        field("operation_id", id()),
        field("request_fingerprint", digest()),
        field("authorized_node_id", id()),
        field("delete_id", id()),
        field("disk_id", id()),
        field("volume_id", id()),
        field("cat_id", id()),
        field("placement_epoch", epoch()),
        field("expected_attachment_id", id()),
        field("expected_epoch", wire_u64()),
        field("expected_head", remote_head_schema()),
        field("disposition", closed(&["discard_with_cat"])),
        field("persistent_dispositions_digest", digest()),
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

#[cfg(feature = "proposed-node-residue-reclamation")]
fn residue_reclaim_proof_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "ordinary_release",
                vec![field("current_volume", volume_record_schema())],
            ),
            variant(
                "normal_delete_completion",
                vec![field("completion", delete_completion_receipt_schema())],
            ),
            variant(
                "disposable_root_delete_completion",
                vec![
                    field("completion", delete_completion_receipt_schema()),
                    field("consumed_authorization", authorization_record_schema()),
                ],
            ),
        ],
    )
}

#[cfg(feature = "proposed-node-residue-reclamation")]
fn runtime_residue_authority_outcome_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "retained",
                vec![field(
                    "reason",
                    closed(&[
                        "no_authority_record",
                        "current_or_newer_owner",
                        "release_not_recorded",
                        "delete_incomplete",
                        "lineage_mismatch",
                        "unique_local_tail",
                        "unsupported_disk_kind",
                    ]),
                )],
            ),
            variant(
                "reclaimable",
                vec![field("proof", residue_reclaim_proof_schema())],
            ),
        ],
    )
}

#[cfg(feature = "proposed-node-residue-reclamation")]
fn runtime_residue_authority_request_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("session", session_binding_schema()),
        field("lineage", residue_data_directory_lineage_schema()),
    ])
}

#[cfg(feature = "proposed-node-residue-reclamation")]
fn runtime_residue_authority_success_schema() -> Schema {
    object(vec![
        field("version", version()),
        field("session", session_binding_schema()),
        field("lineage", residue_data_directory_lineage_schema()),
        field("outcome", runtime_residue_authority_outcome_schema()),
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

fn acquire_origin_schema() -> Schema {
    union(
        "kind",
        vec![
            variant("normal", vec![field("transition_id", random_id())]),
            variant("takeover", vec![field("authorization_id", id())]),
        ],
    )
}

#[cfg(feature = "proposed-node-residue-reclamation")]
fn residue_data_directory_lineage_schema() -> Schema {
    object(vec![
        field("workspace_id", id()),
        field("cat_id", id()),
        field("disk_id", id()),
        field("disk_kind", closed(&["root", "persistent"])),
        field("volume_id", id()),
        field("attachment_id", id()),
        field("attachment_epoch", wire_u64()),
        field("acquire_origin", acquire_origin_schema()),
        field("node_id", id()),
        field("desired_revision", revision()),
        field("spec_digest", digest()),
        field("placement", assigned_placement_schema()),
        field("placement_epoch", epoch()),
        field("acquisition", authorized_serving_acquire_schema()),
        field("acquisition_digest", digest()),
        field("local_durable_generation", wire_u64()),
        field("remote_durable_generation", wire_u64()),
        field("remote_head", remote_head_schema()),
        field("pending_pack_count", wire_u64()),
        field("fenced", Schema::Bool),
    ])
}

#[cfg(feature = "proposed-node-residue-reclamation")]
fn authorized_serving_acquire_schema() -> Schema {
    union(
        "kind",
        vec![
            variant(
                "normal",
                vec![
                    field("request", normal_acquire_request_schema()),
                    field("result", normal_acquire_result_schema()),
                ],
            ),
            variant(
                "takeover",
                vec![
                    field("authorization", object(takeover_authorization_fields())),
                    field("receipt", object(takeover_consumed_receipt_fields())),
                ],
            ),
        ],
    )
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
        "runtime_spine_error",
        #[cfg(feature = "proposed-node-residue-reclamation")]
        "runtime_residue_authority_request",
        #[cfg(feature = "proposed-node-residue-reclamation")]
        "runtime_residue_authority_success",
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
                "session_expired",
                vec![
                    field("node_id", id()),
                    field("agent_session_epoch", epoch()),
                    field("lease_deadline_unix_ms", wire_u64()),
                    field("server_time_unix_ms", wire_u64()),
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
        field(
            "provider_scope",
            object(vec![
                field("provider", id()),
                field("partition", id()),
                field("account_id", id()),
                field("region", id()),
            ]),
        ),
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
            variant(
                "provision_object_write_authority",
                vec![
                    field("expected_policy_revision", epoch()),
                    field(
                        "object_provider_scope",
                        object(vec![
                            field("provider", id()),
                            field("partition", id()),
                            field("account_id", id()),
                            field("region", id()),
                        ]),
                    ),
                    field("workload_principal_id", string(StringRule::AsciiText)),
                    field("object_store_scope_id", string(StringRule::AsciiText)),
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
                "object_write_authority_provisioned",
            ]),
        ),
        field("identity_state", closed(&["provisioned", "retired"])),
        field("policy_revision", epoch()),
        field("writer_authority_id", nullable(id())),
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

// These schemas are immutable protocol metadata. Constructing a deeply nested
// contract tree for every request would put avoidable allocation on the hot
// path, so each explicit decoder shares one lazily initialized tree.
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
static RUNTIME_SPINE_ERROR_SCHEMA: LazyLock<Schema> = LazyLock::new(runtime_spine_error_schema);
#[cfg(feature = "proposed-node-residue-reclamation")]
static RUNTIME_RESIDUE_AUTHORITY_REQUEST_SCHEMA: LazyLock<Schema> =
    LazyLock::new(runtime_residue_authority_request_schema);
#[cfg(feature = "proposed-node-residue-reclamation")]
static RUNTIME_RESIDUE_AUTHORITY_SUCCESS_SCHEMA: LazyLock<Schema> =
    LazyLock::new(runtime_residue_authority_success_schema);
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

pub fn decode_runtime_spine_error(bytes: &[u8]) -> Result<RuntimeSpineError, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeSpineError,
        RUNTIME_SPINE_ERROR_MAX_WIRE_BYTES,
        &RUNTIME_SPINE_ERROR_SCHEMA,
        validate_runtime_spine_error,
    )
}

#[cfg(feature = "proposed-node-residue-reclamation")]
pub fn decode_runtime_residue_authority_request(
    bytes: &[u8],
) -> Result<RuntimeResidueAuthorityRequest, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeResidueAuthorityRequest,
        RUNTIME_RESIDUE_AUTHORITY_REQUEST_MAX_WIRE_BYTES,
        &RUNTIME_RESIDUE_AUTHORITY_REQUEST_SCHEMA,
        validate_runtime_residue_authority_request,
    )
}

#[cfg(feature = "proposed-node-residue-reclamation")]
pub fn decode_runtime_residue_authority_success(
    bytes: &[u8],
) -> Result<RuntimeResidueAuthoritySuccess, ContractError> {
    decode(
        bytes,
        ContractName::RuntimeResidueAuthoritySuccess,
        RUNTIME_RESIDUE_AUTHORITY_SUCCESS_MAX_WIRE_BYTES,
        &RUNTIME_RESIDUE_AUTHORITY_SUCCESS_SCHEMA,
        validate_runtime_residue_authority_success,
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

pub fn encode_runtime_spine_error(value: &RuntimeSpineError) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeSpineError,
        decode_runtime_spine_error,
    )
}

#[cfg(feature = "proposed-node-residue-reclamation")]
pub fn encode_runtime_residue_authority_request(
    value: &RuntimeResidueAuthorityRequest,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeResidueAuthorityRequest,
        decode_runtime_residue_authority_request,
    )
}

#[cfg(feature = "proposed-node-residue-reclamation")]
pub fn encode_runtime_residue_authority_success(
    value: &RuntimeResidueAuthoritySuccess,
) -> Result<Vec<u8>, ContractError> {
    encode(
        value,
        ContractName::RuntimeResidueAuthoritySuccess,
        decode_runtime_residue_authority_success,
    )
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
        // Every field is context-free scalar-validated by the schema, and the
        // Host side of the binding is deliberately absent from the request.
        RuntimeNodeAuthorityMutation::ProvisionObjectWriteAuthority { .. } => {}
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
        RuntimeNodeAuthorityOutcome::ObjectWriteAuthorityProvisioned => {
            result.identity_state == NodeIdentityState::Provisioned
        }
    };
    // The assigned writer authority ID belongs to exactly one outcome, and it
    // is always the closed shape Control derives. A result claiming any other
    // outcome may not smuggle one in.
    let valid = valid
        && match (result.outcome, result.writer_authority_id.as_ref()) {
            (
                RuntimeNodeAuthorityOutcome::ObjectWriteAuthorityProvisioned,
                Some(writer_authority_id),
            ) => valid_object_write_writer_authority_id(writer_authority_id.as_str()),
            (RuntimeNodeAuthorityOutcome::ObjectWriteAuthorityProvisioned, None) => false,
            (_, Some(_)) => false,
            (_, None) => true,
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
            ContractName::ContractError,
            &path(&["loaded_kids"]),
            LimitKind::ArrayItems,
            64,
        ));
    }
    validate_scalar_order(
        loaded_kids,
        ContractName::ContractError,
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
                && remote_head_valid(&authorization.expected_head)
        }
        (VolumeAuthorization::Takeover(authorization), AuthorizationState::Consumed(receipt)) => {
            match receipt.as_ref() {
                AuthorizationConsumedReceipt::Takeover(receipt) => {
                    authorization.new_attachment_id != authorization.expected_attachment_id
                        && remote_head_valid(&authorization.expected_head)
                        && receipt.authorization_id == authorization.authorization_id
                        && receipt.host_fence_event_id == authorization.host_fence_event_id
                        && receipt.volume_id == authorization.volume_id
                        && receipt.new_attachment_id == authorization.new_attachment_id
                        && valid_next_epoch(authorization.expected_epoch, receipt.resulting_epoch)
                        && receipt.resulting_head == authorization.expected_head
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
                    DisposableDeleteIsolationBasis::LifecycleStrongStop { node_id, .. } => {
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
                        DisposableDeleteIsolationBasis::LifecycleStrongStop { node_id, .. } => {
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
        LastVolumeTransition::NormalAcquire {
            request, result, ..
        } => {
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
        LastVolumeTransition::Release {
            request, result, ..
        } => {
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
        LastVolumeTransition::BeginDelete {
            request, result, ..
        } => {
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
        Some(LastVolumeTransition::Takeover {
            authorization_id, ..
        })
        | Some(LastVolumeTransition::BeginDisposableDelete {
            authorization_id, ..
        }) => Some(authorization_id),
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
                Some(LastVolumeTransition::Takeover { authorization_id, .. })
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
            Some(LastVolumeTransition::BeginDisposableDelete { authorization_id, .. })
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

#[cfg(feature = "proposed-node-residue-reclamation")]
fn residue_acquisition_is_exact(lineage: &ResidueDataDirectoryLineage) -> bool {
    let receipt_is_exact = match (&lineage.acquire_origin, &lineage.acquisition) {
        (
            AcquireOrigin::Normal { transition_id },
            AuthorizedServingAcquire::Normal { request, result },
        ) => {
            request.volume_id == lineage.volume_id
                && request.transition_id == *transition_id
                && request.attachment_id == lineage.attachment_id
                && request.placement_epoch == lineage.placement_epoch
                && result.volume_id == lineage.volume_id
                && result.transition_id == *transition_id
                && result.attachment_id == lineage.attachment_id
                && valid_next_epoch(request.expected_unowned_epoch, result.resulting_epoch)
                && result.resulting_epoch == lineage.attachment_epoch
                && result.lease_expires_at.get() >= request.lease_duration_ms
                && remote_head_same_or_later(&lineage.remote_head, &result.resulting_head)
        }
        (
            AcquireOrigin::Takeover { authorization_id },
            AuthorizedServingAcquire::Takeover {
                authorization,
                receipt,
            },
        ) => {
            authorization.authorization_id == *authorization_id
                && authorization.authorized_node_id == lineage.node_id
                && authorization.volume_id == lineage.volume_id
                && authorization.new_attachment_id != authorization.expected_attachment_id
                && remote_head_valid(&authorization.expected_head)
                && authorization.new_attachment_id == lineage.attachment_id
                && authorization.new_placement_epoch == lineage.placement_epoch
                && receipt.authorization_id == authorization.authorization_id
                && receipt.host_fence_event_id == authorization.host_fence_event_id
                && receipt.volume_id == authorization.volume_id
                && receipt.new_attachment_id == authorization.new_attachment_id
                && valid_next_epoch(authorization.expected_epoch, receipt.resulting_epoch)
                && receipt.resulting_epoch == lineage.attachment_epoch
                && receipt.resulting_head == authorization.expected_head
                && receipt.consumed_at <= authorization.not_after
                && receipt
                    .consumed_at
                    .get()
                    .checked_add(authorization.lease_duration_ms)
                    .is_some_and(|value| value <= MAX_WIRE_INTEGER)
                && remote_head_same_or_later(&lineage.remote_head, &receipt.resulting_head)
        }
        _ => false,
    };
    receipt_is_exact
        && super::canonical::residue_acquisition_digest(&lineage.acquisition)
            .is_ok_and(|digest| digest == lineage.acquisition_digest)
}

#[cfg(feature = "proposed-node-residue-reclamation")]
fn residue_lineage_valid(lineage: &ResidueDataDirectoryLineage) -> bool {
    lineage.attachment_epoch.get() > 0
        && !lineage.node_id.as_str().is_empty()
        && lineage.placement.node_id == lineage.node_id
        && residue_acquisition_is_exact(lineage)
        && lineage.remote_head.generation == lineage.remote_durable_generation
        && remote_head_valid(&lineage.remote_head)
        && lineage.local_durable_generation >= lineage.remote_durable_generation
        && ((lineage.local_durable_generation == lineage.remote_durable_generation
            && lineage.pending_pack_count.get() == 0)
            || (lineage.local_durable_generation > lineage.remote_durable_generation
                && lineage.pending_pack_count.get() > 0))
}

/// Context-free closure for the only three authority proofs which may qualify
/// an exact retained data-directory lineage for deletion.  Filesystem
/// descriptor identity and live-owner absence remain Node-local preconditions.
#[cfg(feature = "proposed-node-residue-reclamation")]
pub fn residue_reclaim_proof_is_closed(
    lineage: &ResidueDataDirectoryLineage,
    proof: &ResidueReclaimProof,
) -> bool {
    if !residue_lineage_valid(lineage) {
        return false;
    }
    match proof {
        ResidueReclaimProof::OrdinaryRelease { current_volume } => {
            if lineage.local_durable_generation != lineage.remote_durable_generation
                || !volume_record_valid(current_volume)
                || current_volume.volume_id != lineage.volume_id
            {
                return false;
            }
            matches!(
                &current_volume.last_transition,
                Some(LastVolumeTransition::Release {
                    request, result, ..
                })
                    if request.volume_id == lineage.volume_id
                        && request.attachment_id == lineage.attachment_id
                        && request.expected_epoch == lineage.attachment_epoch
                        && result.released_attachment_id == lineage.attachment_id
                        && remote_head_same_or_later(
                            &result.resulting_head,
                            &lineage.remote_head,
                        )
            )
        }
        ResidueReclaimProof::NormalDeleteCompletion { completion } => {
            if lineage.local_durable_generation != lineage.remote_durable_generation
                || !delete_completion_valid(completion)
            {
                return false;
            }
            matches!(
                completion.as_ref(),
                DeleteCompletionReceipt::Normal {
                    request,
                    deleting_head,
                    ..
                } if request.disk_id == lineage.disk_id
                    && request.volume_id == lineage.volume_id
                    && valid_next_epoch(
                        lineage.attachment_epoch,
                        request.expected_unowned_epoch,
                    )
                    && remote_head_same_or_later(deleting_head, &lineage.remote_head)
            )
        }
        ResidueReclaimProof::DisposableRootDeleteCompletion {
            completion,
            consumed_authorization,
        } => {
            if lineage.disk_kind != DiskKind::Root
                || !delete_completion_valid(completion)
                || !authorization_record_valid(consumed_authorization)
            {
                return false;
            }
            let (
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
                },
                VolumeAuthorization::DisposableRootDelete(authorization),
                AuthorizationState::Consumed(consumed),
            ) = (
                completion.as_ref(),
                &consumed_authorization.authorization,
                &consumed_authorization.state,
            )
            else {
                return false;
            };
            let AuthorizationConsumedReceipt::BeginDisposableDelete(consumed) = consumed.as_ref()
            else {
                return false;
            };
            disk_id == &lineage.disk_id
                && volume_id == &lineage.volume_id
                && prior_attachment_id == &lineage.attachment_id
                && delete_id == &authorization.delete_id
                && delete_id == &consumed.delete_id
                && authorization_id == &authorization.authorization_id
                && authorization.authorized_node_id == lineage.node_id
                && authorization.disk_id == lineage.disk_id
                && authorization.volume_id == lineage.volume_id
                && authorization.cat_id == lineage.cat_id
                && authorization.expected_attachment_id == lineage.attachment_id
                && authorization.expected_epoch == lineage.attachment_epoch
                && authorization.placement_epoch == lineage.placement.placement_epoch
                && authorization.expected_head == lineage.remote_head
                && consumed.resulting_epoch == *deleting_epoch
                && consumed.resulting_head == *deleting_head
                && completed_at >= &consumed.consumed_at
                && valid_next_epoch(lineage.attachment_epoch, *deleting_epoch)
        }
    }
}

#[cfg(feature = "proposed-node-residue-reclamation")]
fn validate_runtime_residue_authority_request(
    request: &RuntimeResidueAuthorityRequest,
) -> Result<(), ContractError> {
    let contract = ContractName::RuntimeResidueAuthorityRequest;
    let mut candidates = Vec::new();
    if request.session.node_id != request.lineage.node_id
        || request.session.node_id != request.lineage.placement.node_id
    {
        candidates.push(Candidate::at(
            &path(&["lineage", "node_id"]),
            MalformedProblem::InvalidValue,
        ));
    }
    if !residue_lineage_valid(&request.lineage) {
        candidates.push(Candidate::at(
            &path(&["lineage"]),
            MalformedProblem::InvalidValue,
        ));
    }
    if let Some(candidate) = choose(candidates) {
        return Err(malformed(contract, candidate));
    }
    Ok(())
}

#[cfg(feature = "proposed-node-residue-reclamation")]
fn validate_runtime_residue_authority_success(
    success: &RuntimeResidueAuthoritySuccess,
) -> Result<(), ContractError> {
    let contract = ContractName::RuntimeResidueAuthoritySuccess;
    let mut candidates = Vec::new();
    if (success.session.node_id != success.lineage.node_id
        || success.session.node_id != success.lineage.placement.node_id)
        || !residue_lineage_valid(&success.lineage)
    {
        candidates.push(Candidate::at(
            &path(&["lineage"]),
            MalformedProblem::InvalidValue,
        ));
    }
    if let RuntimeResidueAuthorityOutcome::Reclaimable { proof } = &success.outcome {
        if !residue_reclaim_proof_is_closed(&success.lineage, proof) {
            candidates.push(Candidate::at(
                &path(&["outcome", "proof"]),
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
        ContractErrorDetail::SessionExpired {
            lease_deadline_unix_ms,
            server_time_unix_ms,
            ..
        } => server_time_unix_ms >= lease_deadline_unix_ms,
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

fn child(path: &[PathSegment], key: &str) -> Vec<PathSegment> {
    let mut result = path.to_vec();
    result.push(PathSegment::Key(key.to_owned()));
    result
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{decode_contract_error, value_bytes};
    use crate::runtime_reconciliation::{ContractErrorDetail, ContractName, MalformedProblem};

    fn malformed_payload_error(contract: &str) -> Vec<u8> {
        value_bytes(&json!({
            "version": 1,
            "error": {
                "code": "malformed_payload",
                "contract": contract,
                "json_pointer": "",
                "problem": "invalid_value"
            },
            "message": "payload rejected"
        }))
    }

    #[test]
    fn active_contract_name_remains_decodable() {
        let decoded = decode_contract_error(&malformed_payload_error("contract_error")).unwrap();

        assert!(matches!(
            decoded.error.as_ref(),
            ContractErrorDetail::MalformedPayload {
                contract: ContractName::ContractError,
                problem: MalformedProblem::InvalidValue,
                ..
            }
        ));
    }

    #[test]
    fn retired_authority_contract_names_are_rejected_at_the_enum_boundary() {
        for retired in [
            "desired_read_request",
            "desired_read_snapshot",
            "desired_runtime_spec",
            "runtime_checkpoint",
            "runtime_volume_transition_request",
            "runtime_volume_transition_success",
            "runtime_volume_transition_evidence_request",
            "runtime_volume_transition_evidence_success",
            "runtime_volume_transition_error",
            "node_observation",
            "observation_acceptance",
            "operation",
        ] {
            let error = decode_contract_error(&malformed_payload_error(retired)).unwrap_err();
            match error.error.as_ref() {
                ContractErrorDetail::MalformedPayload {
                    contract,
                    json_pointer,
                    problem,
                } => {
                    assert_eq!(*contract, ContractName::ContractError, "{retired}");
                    assert_eq!(json_pointer.as_str(), "/error/contract", "{retired}");
                    assert_eq!(*problem, MalformedProblem::InvalidValue, "{retired}");
                }
                other => panic!("unexpected retired-name error for {retired}: {other:?}"),
            }
        }
    }
}
