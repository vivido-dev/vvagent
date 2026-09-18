//! Positional addresses for presenters (plan §6.3).
//!
//! One ordered path across the nested runtimes: `s` space, `t` tab, `w` window, `f` frame,
//! `p` pane. `s2t2w3f1p2` is a Vivida space, tab and window hosting a `vvmux` frame and pane.
//!
//! Two properties carry the design:
//!
//! **Omitted segments are wildcards, not values inherited from the caller.** An agent in `vvmux`
//! pane 7 asking for `p2` means pane 2 in that session whether or not it shares a frame — pane ids
//! are session-unique, and filling in the caller's `f1` would miss a pane sitting in frame 2, which
//! is the case the short form exists to serve.
//!
//! **An address is a locator, never an identity.** Spaces and tabs are display positions that move
//! when their siblings are reordered; windows, frames and panes are stable ids that are nonetheless
//! reused, because `vvmux` restarts its counters at 1. Resolve to an `endpoint_id` at use time and
//! store the id.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ErrorCode, MeshError, Result};

/// Longest legal rendering, so a parser never allocates on an unbounded string.
pub const MAX_ADDRESS_BYTES: usize = 64;

/// One level of the containment hierarchy. The `u8` discriminants *are* the containment order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Space = 0,
    Tab = 1,
    Window = 2,
    Frame = 3,
    Pane = 4,
}

/// Every level, outermost first.
pub const LEVELS: [Level; 5] = [
    Level::Space,
    Level::Tab,
    Level::Window,
    Level::Frame,
    Level::Pane,
];

impl Level {
    pub fn letter(self) -> char {
        match self {
            Self::Space => 's',
            Self::Tab => 't',
            Self::Window => 'w',
            Self::Frame => 'f',
            Self::Pane => 'p',
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Space => "space",
            Self::Tab => "tab",
            Self::Window => "window",
            Self::Frame => "frame",
            Self::Pane => "pane",
        }
    }

    pub fn from_letter(letter: char) -> Option<Self> {
        match letter {
            's' => Some(Self::Space),
            't' => Some(Self::Tab),
            'w' => Some(Self::Window),
            'f' => Some(Self::Frame),
            'p' => Some(Self::Pane),
            _ => None,
        }
    }

    /// Whether this level's index is unique across a whole runtime instance.
    ///
    /// Established, not assumed: Vivida documents `window_id` as globally unique while calling
    /// workspace and tab numbers one-based *displayed positions*, and `vvmux` allocates its pane
    /// and frame ids from monotonic per-session counters. A tab position repeats in every space,
    /// which is why `t` is the one level that cannot stand alone.
    pub fn is_instance_unique(self) -> bool {
        !matches!(self, Self::Tab)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Segment {
    pub level: Level,
    pub index: u32,
}

/// An ordered, gap-tolerant subset of levels.
///
/// Any subset is legal as long as it is in containment order with no repeats: `s2p1` means "pane 1
/// somewhere under space 2", which is meaningful under wildcard matching.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Address {
    segments: Vec<Segment>,
}

impl Address {
    /// Build from segments, enforcing order and uniqueness.
    pub fn new(segments: Vec<Segment>) -> Result<Self> {
        let mut last: Option<Level> = None;
        for segment in &segments {
            if segment.index == 0 {
                return Err(invalid("an address index is one-based"));
            }
            if let Some(previous) = last
                && segment.level <= previous
            {
                return Err(invalid(format!(
                    "`{}` is out of containment order or repeated; use s, t, w, f, p in that order",
                    segment.level.letter()
                )));
            }
            last = Some(segment.level);
        }
        Ok(Self { segments })
    }

    pub fn parse(value: &str) -> Result<Self> {
        if value.is_empty() {
            return Err(invalid("an address needs at least one segment"));
        }
        if value.len() > MAX_ADDRESS_BYTES {
            return Err(invalid(format!(
                "an address is at most {MAX_ADDRESS_BYTES} bytes"
            )));
        }
        let mut segments = Vec::new();
        let mut chars = value.chars().peekable();
        while let Some(letter) = chars.next() {
            let level = Level::from_letter(letter).ok_or_else(|| {
                invalid(format!(
                    "`{letter}` is not an address level; use s, t, w, f or p"
                ))
            })?;
            let mut digits = String::new();
            while chars.peek().is_some_and(char::is_ascii_digit) {
                digits.push(chars.next().expect("peeked"));
            }
            if digits.is_empty() {
                return Err(invalid(format!("`{letter}` has no index")));
            }
            if digits.len() > 1 && digits.starts_with('0') {
                return Err(invalid(format!("`{letter}{digits}` has a leading zero")));
            }
            let index: u32 = digits
                .parse()
                .map_err(|_| invalid(format!("`{digits}` does not fit an address index")))?;
            segments.push(Segment { level, index });
        }
        Self::new(segments)
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn get(&self, level: Level) -> Option<u32> {
        self.segments
            .iter()
            .find(|segment| segment.level == level)
            .map(|segment| segment.index)
    }

    /// The innermost level this address names.
    pub fn depth(&self) -> Option<Level> {
        self.segments.last().map(|segment| segment.level)
    }

    /// Whether this (complete) address satisfies a (possibly partial) pattern.
    ///
    /// Every level the pattern names must be present here with the same index. Levels the pattern
    /// omits are wildcards — *not* holes to be filled from a caller, which is what lets `p2` find
    /// a pane in another frame.
    pub fn satisfies(&self, pattern: &Address) -> bool {
        pattern
            .segments
            .iter()
            .all(|wanted| self.get(wanted.level) == Some(wanted.index))
    }

    /// How many leading levels two addresses agree on, outermost first.
    ///
    /// Used only to prefer the caller's own neighbourhood when several endpoints match. Counting
    /// stops at the first level where they disagree or where either is silent, so an address with
    /// a gap cannot claim depth it does not have.
    pub fn shared_prefix(&self, other: &Address) -> usize {
        let mut shared = 0;
        for level in LEVELS {
            match (self.get(level), other.get(level)) {
                (Some(mine), Some(theirs)) if mine == theirs => shared += 1,
                _ => break,
            }
        }
        shared
    }

    /// The innermost segment whose index survives a move.
    ///
    /// Spaces and tabs are positions and change when a window is dragged elsewhere; a window id,
    /// frame or pane keeps its number. So this is the part of an address that still identifies the
    /// same thing after the move, which is what lets a runtime say "whatever was at w42 is now at
    /// s3t1w42" without knowing any endpoint ids.
    pub fn stable_anchor(&self) -> Option<Segment> {
        self.segments
            .iter()
            .rev()
            .find(|segment| segment.level.is_instance_unique() && segment.level != Level::Space)
            .copied()
    }

    /// Extend a host's address with the levels a nested runtime contributes.
    ///
    /// This is how a `vvmux` session running inside a Vivida window learns its full path: the host
    /// passes `s2t2w3`, `vvmux` appends its own `f1p2`. Refused when the two overlap, because that
    /// would mean two runtimes each claiming the same level.
    pub fn join(prefix: &Address, suffix: &Address) -> Result<Self> {
        if let (Some(outermost), Some(innermost)) =
            (suffix.segments.first(), prefix.segments.last())
            && outermost.level <= innermost.level
        {
            return Err(invalid(format!(
                "`{suffix}` starts at `{}`, which `{prefix}` already covers",
                outermost.level.name()
            )));
        }
        let mut segments = prefix.segments.clone();
        segments.extend_from_slice(&suffix.segments);
        Self::new(segments)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for segment in &self.segments {
            write!(f, "{}{}", segment.level.letter(), segment.index)?;
        }
        Ok(())
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

fn invalid(message: impl Into<String>) -> MeshError {
    MeshError::new(ErrorCode::InvalidRequest, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(value: &str) -> Address {
        Address::parse(value).unwrap()
    }

    #[test]
    fn every_documented_shape_parses_and_round_trips() {
        for value in [
            "s2t2w3f1p2",
            "t1w2f1p3",
            "f1p2",
            "s2t2w3",
            "s2",
            "p2",
            "w42",
            "s10t11w12",
        ] {
            let parsed = addr(value);
            assert_eq!(parsed.to_string(), value, "round trip of {value}");
        }
    }

    #[test]
    fn a_subset_with_a_gap_is_legal() {
        // "pane 1 somewhere under space 2" — meaningful under wildcard matching, so refusing it
        // would be arbitrary.
        let parsed = addr("s2p1");
        assert_eq!(parsed.get(Level::Space), Some(2));
        assert_eq!(parsed.get(Level::Pane), Some(1));
        assert_eq!(parsed.get(Level::Tab), None);
    }

    #[test]
    fn malformed_addresses_are_refused_with_a_reason() {
        for (value, why) in [
            ("", "empty"),
            ("p", "no index"),
            ("2p", "no leading letter"),
            ("p0", "zero index"),
            ("p01", "leading zero"),
            ("p1p2", "repeated level"),
            ("p1f2", "out of order"),
            ("t2s1", "out of order"),
            ("x1", "unknown level"),
            ("p1x2", "unknown level after a valid segment"),
        ] {
            assert!(
                Address::parse(value).is_err(),
                "`{value}` should be refused ({why})"
            );
        }
        assert!(
            Address::parse(&"p1".repeat(40)).is_err(),
            "over the byte cap"
        );
    }

    #[test]
    fn a_pattern_matches_across_the_levels_it_omits() {
        // The case the short form exists for: p2 finds pane 2 in a *different* frame.
        let in_frame_two = addr("s2t2w3f2p2");
        assert!(in_frame_two.satisfies(&addr("p2")));
        assert!(in_frame_two.satisfies(&addr("f2")));
        assert!(in_frame_two.satisfies(&addr("w3")));
        assert!(in_frame_two.satisfies(&addr("s2p2")));
        assert!(in_frame_two.satisfies(&addr("s2t2w3f2p2")));

        assert!(
            !in_frame_two.satisfies(&addr("p3")),
            "a named level must agree"
        );
        assert!(
            !in_frame_two.satisfies(&addr("f1p2")),
            "every named level must agree"
        );
        assert!(!in_frame_two.satisfies(&addr("s1")));
    }

    #[test]
    fn omitted_segments_are_wildcards_not_inherited_values() {
        // If `p2` were completed from the caller's own address it would become s2t2w3f1p2 and miss
        // the pane that actually exists in frame 2. This is the distinction M2.5 exists to hold.
        let caller = addr("s2t2w3f1p7");
        let target = addr("s2t2w3f2p2");
        let pattern = addr("p2");

        assert!(target.satisfies(&pattern));
        let naive_completion = addr("s2t2w3f1p2");
        assert!(
            !target.satisfies(&naive_completion),
            "inheritance would have looked in the wrong frame"
        );
        assert_eq!(caller.shared_prefix(&target), 3, "they share s2t2w3");
    }

    #[test]
    fn shared_prefix_stops_at_the_first_disagreement_or_gap() {
        assert_eq!(addr("s2t2w3").shared_prefix(&addr("s2t2w3")), 3);
        assert_eq!(addr("s2t2w3").shared_prefix(&addr("s2t2w9")), 2);
        assert_eq!(addr("s2t2w3").shared_prefix(&addr("s9t2w3")), 0);
        // A gap cannot claim depth: s2p1 is silent about tabs, so agreement stops there.
        assert_eq!(addr("s2t2w3").shared_prefix(&addr("s2p1")), 1);
        assert_eq!(addr("f1p2").shared_prefix(&addr("s2t2w3")), 0);
    }

    #[test]
    fn only_tabs_need_their_parent() {
        assert!(!Level::Tab.is_instance_unique());
        for level in [Level::Space, Level::Window, Level::Frame, Level::Pane] {
            assert!(
                level.is_instance_unique(),
                "{} should stand alone",
                level.name()
            );
        }
    }

    #[test]
    fn the_stable_anchor_is_the_innermost_segment_that_survives_a_move() {
        assert_eq!(
            addr("s2t2w3f1p2").stable_anchor(),
            Some(Segment {
                level: Level::Pane,
                index: 2
            })
        );
        assert_eq!(
            addr("s2t2w3").stable_anchor(),
            Some(Segment {
                level: Level::Window,
                index: 3
            })
        );
        assert_eq!(
            addr("f7").stable_anchor(),
            Some(Segment {
                level: Level::Frame,
                index: 7
            })
        );
        // Positions alone anchor nothing: both change when things are reordered.
        assert_eq!(addr("s2t2").stable_anchor(), None);
        assert_eq!(addr("s2").stable_anchor(), None);
    }

    #[test]
    fn a_nested_runtime_joins_its_levels_onto_its_host() {
        let host = addr("s2t2w3");
        let inner = addr("f1p2");
        assert_eq!(Address::join(&host, &inner).unwrap(), addr("s2t2w3f1p2"));

        // Two runtimes cannot both claim a level.
        assert!(Address::join(&addr("s2t2w3"), &addr("w4p1")).is_err());
        assert!(Address::join(&addr("f1"), &addr("f2")).is_err());
        // Joining onto nothing is just the suffix.
        assert_eq!(Address::join(&Address::default(), &inner).unwrap(), inner);
    }

    #[test]
    fn addresses_serialize_as_their_canonical_string() {
        let value = serde_json::to_string(&addr("s2t2w3f1p2")).unwrap();
        assert_eq!(value, "\"s2t2w3f1p2\"");
        let back: Address = serde_json::from_str(&value).unwrap();
        assert_eq!(back, addr("s2t2w3f1p2"));
        assert!(serde_json::from_str::<Address>("\"p1p2\"").is_err());
    }
}
