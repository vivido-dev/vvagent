//! Keep endpoint addresses in step with a runtime's layout.
//!
//! An address is a position, and positions move: dragging a window to another space changes `s`,
//! reordering tabs changes `t`. The environment a pane inherited at creation cannot be edited
//! afterwards, so something has to re-derive addresses when the layout changes.
//!
//! That something is the watcher, asking its *own* runtime — which is the arrangement §3.2 already
//! settled for activation. Two properties fall out of doing it here rather than in the runtime:
//!
//! - **Vivida needs no code for it.** Its `layout` is already the authoritative view, already
//!   accounts for reordering, and already has to be correct for every other automation caller.
//!   Eight scattered `pane_index` writes could each forget to publish; one reader cannot.
//! - **Only the address moves.** Reconciling calls the same path as `vvagent readdress`, which
//!   changes an endpoint's position and nothing else — not its id, its mailbox, or its pending
//!   work. A window dragged across a workspace loses no mail.

use std::process::{Command, Stdio};

use agent_mesh_core::{Address, ErrorCode, Level, MeshError, Opaque, Result, Segment};
use agent_mesh_store::Store;
use serde_json::Value;

/// A runtime layout command must not stall the watcher.
const TIMEOUT_SECS: u64 = 15;

/// One endpoint's position, as the runtime currently sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Placement {
    /// The part of the address that survives a move, and therefore what an endpoint is found by.
    ///
    /// A window keeps its id when it is dragged to another space or tab; a vvmux pane keeps its id
    /// when it is moved to another frame. Both are instance-unique, which is what makes either
    /// usable as an anchor — the level differs by runtime, so it is carried rather than assumed.
    pub anchor: Segment,
    pub address: Address,
}

/// What one reconcile pass changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Reconciled {
    pub seen: usize,
    pub moved: Vec<(String, String, String)>,
}

/// Read a runtime's layout and correct any endpoint whose address has drifted.
pub fn run(store: &mut Store, scope: &Opaque, command: &str) -> Result<Reconciled> {
    let layout = capture(command)?;
    let placements = placements(&layout);
    let mut result = Reconciled {
        seen: placements.len(),
        ..Reconciled::default()
    };

    let endpoints = store.list_endpoints()?;
    for placement in placements {
        // The anchor is instance-unique and survives the move, so it is what links the endpoint to
        // its new position without anyone needing to know an endpoint id.
        let anchor = Address::new(vec![placement.anchor])?;
        let matches: Vec<_> = endpoints
            .iter()
            .filter(|endpoint| endpoint.locator.runtime_instance_id == *scope)
            .filter(|endpoint| {
                endpoint
                    .locator
                    .address
                    .as_ref()
                    .is_some_and(|current| current.satisfies(&anchor))
            })
            .collect();
        // Two endpoints claiming one window is a runtime bug, not something to pick a winner for.
        let [endpoint] = matches.as_slice() else {
            continue;
        };
        let current = endpoint.locator.address.as_ref();
        if current == Some(&placement.address) {
            continue;
        }
        store.set_address(&endpoint.endpoint_id, Some(&placement.address))?;
        result.moved.push((
            endpoint.endpoint_id.as_str().to_owned(),
            current.map(ToString::to_string).unwrap_or_default(),
            placement.address.to_string(),
        ));
    }
    Ok(result)
}

/// Extract every pane's position from a Vivida-shaped layout document.
///
/// Deliberately tolerant: a runtime with no spaces omits `workspace_index`, one with no tabs omits
/// `tab_index`, and the address simply has fewer segments. A pane with no `window_id` is skipped
/// rather than guessed at.
pub fn placements(layout: &Value) -> Vec<Placement> {
    let mut out = Vec::new();
    let workspaces = layout["workspaces"].as_array().cloned().unwrap_or_default();
    // A runtime with no spaces still reports tabs; treat the whole document as one implicit space.
    let spaces: Vec<(Option<u32>, Value)> = if workspaces.is_empty() {
        vec![(None, layout.clone())]
    } else {
        workspaces
            .into_iter()
            .map(|workspace| (index_of(&workspace, "workspace_index"), workspace))
            .collect()
    };

    for (space, workspace) in spaces {
        let tabs = workspace["tabs"].as_array().cloned().unwrap_or_default();
        let groups: Vec<(Option<u32>, Option<u32>, Value)> = if tabs.is_empty() {
            vec![(None, None, workspace.clone())]
        } else {
            tabs.into_iter()
                .map(|tab| (index_of(&tab, "tab_index"), index_of(&tab, "tab_id"), tab))
                .collect()
        };
        for (tab, tab_id, group) in groups {
            for pane in group["panes"].as_array().cloned().unwrap_or_default() {
                if let Some(placement) = window_placement(space, tab, &pane) {
                    out.push(placement);
                } else if let Some(placement) = frame_placement(tab_id, &pane) {
                    out.push(placement);
                }
            }
        }
    }
    out
}

/// A window-shaped pane: `sNtNwN`, anchored on the window id that survives a move.
///
/// This is Vivida's and Vivido's reading. A pane with no `window_id` is not one of theirs.
fn window_placement(space: Option<u32>, tab: Option<u32>, pane: &Value) -> Option<Placement> {
    let window_id = index_of(pane, "window_id")?;
    let mut segments = Vec::new();
    if let Some(index) = space {
        segments.push(Segment {
            level: Level::Space,
            index,
        });
    }
    if let Some(index) = tab {
        segments.push(Segment {
            level: Level::Tab,
            index,
        });
    }
    let anchor = Segment {
        level: Level::Window,
        index: window_id,
    };
    segments.push(anchor);
    Some(Placement {
        anchor,
        address: Address::new(segments).ok()?,
    })
}

/// A vvmux-shaped pane: `fNpN`, anchored on the pane id that survives a move between frames.
///
/// vvmux names a frame by its stable `tab_id` rather than its display position, because that is
/// what a pane's environment publishes and the two must agree. `display_index` is mutable and
/// zero-based, so it could not be an address index even if they did not have to.
fn frame_placement(tab_id: Option<u32>, pane: &Value) -> Option<Placement> {
    let frame = tab_id?;
    let pane_id = index_of(pane, "pane_id")?;
    let anchor = Segment {
        level: Level::Pane,
        index: pane_id,
    };
    Some(Placement {
        anchor,
        address: Address::new(vec![
            Segment {
                level: Level::Frame,
                index: frame,
            },
            anchor,
        ])
        .ok()?,
    })
}

/// A one-based positive index, or nothing. Zero is not a legal address index.
fn index_of(value: &Value, key: &str) -> Option<u32> {
    let index = value[key].as_u64()?;
    u32::try_from(index).ok().filter(|index| *index > 0)
}

fn capture(command: &str) -> Result<Value> {
    let mut child = shell(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| MeshError::new(ErrorCode::Io, format!("cannot run `{command}`: {err}")))?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(TIMEOUT_SECS);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(MeshError::new(
                    ErrorCode::Io,
                    format!("`{command}` did not answer within {TIMEOUT_SECS}s"),
                ));
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(25)),
            Err(err) => return Err(MeshError::new(ErrorCode::Io, err.to_string())),
        }
    }

    let output = child
        .wait_with_output()
        .map_err(|err| MeshError::new(ErrorCode::Io, err.to_string()))?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr);
        return Err(MeshError::new(
            ErrorCode::Io,
            format!(
                "`{command}` failed: {}",
                detail.lines().next().unwrap_or("no detail")
            ),
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|err| {
        MeshError::new(
            ErrorCode::InvalidRequest,
            format!("`{command}` did not print layout JSON: {err}"),
        )
    })
}

#[cfg(unix)]
fn shell(command: &str) -> Command {
    let mut process = Command::new("sh");
    process.arg("-c").arg(command);
    process
}

#[cfg(windows)]
fn shell(command: &str) -> Command {
    use std::os::windows::process::CommandExt;
    let mut process = Command::new("cmd");
    process
        .args(["/D", "/S", "/C"])
        .raw_arg(format!("\"{command}\""));
    process
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_vivida_layout_yields_a_full_space_tab_window_address() {
        let layout = json!({
            "workspaces": [
                { "workspace_index": 1, "tabs": [
                    { "tab_index": 1, "panes": [{ "window_id": 7 }] },
                    { "tab_index": 2, "panes": [{ "window_id": 9 }, { "window_id": 11 }] }
                ]},
                { "workspace_index": 3, "tabs": [
                    { "tab_index": 1, "panes": [{ "window_id": 42 }] }
                ]}
            ]
        });
        let found: Vec<String> = placements(&layout)
            .into_iter()
            .map(|placement| placement.address.to_string())
            .collect();
        assert_eq!(found, ["s1t1w7", "s1t2w9", "s1t2w11", "s3t1w42"]);
    }

    #[test]
    fn a_runtime_without_spaces_or_tabs_yields_a_shorter_address() {
        // Vivido has windows and, on some platforms, tabs; it has no spaces. The address simply
        // has fewer segments rather than inventing an index for a level that does not exist.
        let tabs_only = json!({ "tabs": [{ "tab_index": 2, "panes": [{ "window_id": 5 }] }] });
        assert_eq!(placements(&tabs_only)[0].address.to_string(), "t2w5");

        let windows_only = json!({ "panes": [{ "window_id": 5 }] });
        assert_eq!(placements(&windows_only)[0].address.to_string(), "w5");
    }

    #[test]
    fn a_pane_without_a_window_id_is_skipped_not_guessed() {
        let layout = json!({
            "workspaces": [{ "workspace_index": 1, "tabs": [{ "tab_index": 1, "panes": [
                { "title": "no id here" },
                { "window_id": 0 },
                { "window_id": 4 }
            ]}]}]
        });
        let found = placements(&layout);
        assert_eq!(found.len(), 1, "only the addressable pane: {found:?}");
        assert_eq!(found[0].address.to_string(), "s1t1w4");
    }

    #[test]
    fn a_vvmux_layout_yields_a_frame_pane_address_anchored_on_the_pane() {
        // vvmux names a frame by its stable `tab_id`, which is what a pane's environment
        // publishes; `display_index` is mutable and zero-based, so it could not be an index.
        let layout = json!({
            "tabs": [
                { "tab_id": 1, "display_index": 0, "panes": [
                    { "pane_id": 1 }, { "pane_id": 2 }
                ]},
                { "tab_id": 2, "display_index": 1, "panes": [{ "pane_id": 4 }] }
            ]
        });

        let found = placements(&layout);
        let addresses: Vec<String> = found
            .iter()
            .map(|placement| placement.address.to_string())
            .collect();
        assert_eq!(addresses, ["f1p1", "f1p2", "f2p4"]);

        // A pane keeps its id when it is moved to another frame, so the pane is what links an
        // endpoint to its new position — the window level does not exist here at all.
        assert!(
            found
                .iter()
                .all(|placement| placement.anchor.level == Level::Pane),
            "a vvmux placement anchors on its pane: {found:?}"
        );
    }

    #[test]
    fn a_window_shaped_pane_wins_over_a_frame_shaped_reading() {
        // Vivida panes carry a local `pane_id` beside their `window_id`. Reading them as vvmux
        // panes would address them by a number that repeats in every tab.
        let layout = json!({
            "workspaces": [{ "workspace_index": 1, "tabs": [
                { "tab_index": 1, "tab_id": 8, "panes": [{ "pane_id": 1, "window_id": 42 }] }
            ]}]
        });

        let found = placements(&layout);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].address.to_string(), "s1t1w42");
        assert_eq!(found[0].anchor.level, Level::Window);
    }

    #[test]
    fn an_empty_layout_yields_nothing_rather_than_failing() {
        assert!(placements(&json!({})).is_empty());
        assert!(placements(&json!({ "workspaces": [] })).is_empty());
    }

    #[test]
    fn a_command_that_prints_nothing_useful_is_an_error_not_an_empty_layout() {
        // Silently treating a broken layout command as "no panes" would quietly stop reconciling.
        assert!(capture("echo not json").is_err());
        assert!(capture("exit 3").is_err());
    }
}
