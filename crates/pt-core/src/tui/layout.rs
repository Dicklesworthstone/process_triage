//! Responsive constraint-based TUI layouts.
//!
//! This module provides responsive layouts that adapt to terminal size using
//! ftui's Flex constraint solver. Layouts automatically switch between breakpoints
//! (minimal, compact, standard, wide) based on terminal dimensions.
//!
//! # Breakpoints
//!
//! - **Wide** (>= 200 cols): Three-pane layout with aux panel
//! - **Standard** (120-199 cols): Two-pane list + detail
//! - **Compact** (80-119 cols): Two-pane with tighter spacing
//! - **Minimal** (< 80 cols): Single-panel layout
//!
//! # Usage
//!
//! ```ignore
//! let layout = ResponsiveLayout::new(frame.area());
//! let areas = layout.main_areas();
//! // Use areas.search, areas.list, areas.detail, areas.status for rendering
//! ```

use ftui::layout::{Constraint, Flex, Rect};
use tracing::{debug, trace};

// ---------------------------------------------------------------------------
// Breakpoints
// ---------------------------------------------------------------------------

/// Terminal size breakpoints for responsive layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Breakpoint {
    /// Minimal terminal (< 80 columns).
    Minimal,
    /// Compact terminal (80-119 columns).
    Compact,
    /// Standard terminal (120-199 columns).
    Standard,
    /// Wide terminal (>= 200 columns).
    Wide,
}

impl Breakpoint {
    /// Determine breakpoint from terminal dimensions.
    pub fn from_size(width: u16, _height: u16) -> Self {
        match width {
            w if w >= 200 => Breakpoint::Wide,
            w if w >= 120 => Breakpoint::Standard,
            w if w >= 80 => Breakpoint::Compact,
            _ => Breakpoint::Minimal,
        }
    }

    /// Minimum columns for this breakpoint.
    pub fn min_cols(&self) -> u16 {
        match self {
            Breakpoint::Minimal => 0,
            Breakpoint::Compact => 80,
            Breakpoint::Standard => 120,
            Breakpoint::Wide => 200,
        }
    }

    /// Human-readable name for logging.
    pub fn name(&self) -> &'static str {
        match self {
            Breakpoint::Minimal => "minimal",
            Breakpoint::Compact => "compact",
            Breakpoint::Standard => "standard",
            Breakpoint::Wide => "wide",
        }
    }
}

// ---------------------------------------------------------------------------
// Area structs
// ---------------------------------------------------------------------------

/// Layout areas for the main view.
#[derive(Debug, Clone, Copy)]
pub struct MainAreas {
    /// Optional header area (goal summary).
    pub header: Option<Rect>,
    /// Search input area at top.
    pub search: Rect,
    /// Main list area (process table).
    pub list: Rect,
    /// Optional detail pane area (two-pane layout).
    pub detail: Option<Rect>,
    /// Optional auxiliary pane (action preview/summary).
    pub aux: Option<Rect>,
    /// Status bar at bottom.
    pub status: Rect,
}

/// Layout areas for the evidence detail view.
#[derive(Debug, Clone, Copy)]
pub struct DetailAreas {
    /// Process info header.
    pub header: Rect,
    /// Evidence ledger area.
    pub evidence: Rect,
    /// Actions panel.
    pub actions: Rect,
}

/// Layout areas for galaxy brain (full math) view.
#[derive(Debug, Clone, Copy)]
pub struct GalaxyBrainAreas {
    /// Math display area.
    pub math: Rect,
    /// Explanation text area.
    pub explanation: Rect,
}

// ---------------------------------------------------------------------------
// Responsive layout calculator
// ---------------------------------------------------------------------------

/// Responsive layout calculator.
///
/// Computes layout areas based on terminal size and current breakpoint.
/// Uses ftui's [`Flex`] solver internally for constraint-based layout.
/// Automatically handles breakpoint transitions and provides smooth
/// degradation for small terminals.
#[derive(Debug, Clone, Copy)]
pub struct ResponsiveLayout {
    /// Terminal area.
    area: Rect,
    /// Current breakpoint.
    breakpoint: Breakpoint,
}

impl ResponsiveLayout {
    /// Create a new responsive layout for the given terminal area.
    pub fn new(area: Rect) -> Self {
        let breakpoint = Breakpoint::from_size(area.width, area.height);

        trace!(
            width = area.width,
            height = area.height,
            breakpoint = breakpoint.name(),
            "layout.calculate"
        );

        Self { area, breakpoint }
    }

    /// Get the current breakpoint.
    pub fn breakpoint(&self) -> Breakpoint {
        self.breakpoint
    }

    /// Get the terminal area.
    pub fn area(&self) -> Rect {
        self.area
    }

    /// Check if terminal is too small for usable display.
    pub fn is_too_small(&self) -> bool {
        self.area.width < 40 || self.area.height < 10
    }

    /// Compute main view layout areas.
    pub fn main_areas(&self) -> MainAreas {
        self.main_areas_with_header(0)
    }

    /// Compute main view layout areas with an optional header row.
    pub fn main_areas_with_header(&self, header_height: u16) -> MainAreas {
        match self.breakpoint {
            Breakpoint::Wide => self.main_areas_wide(header_height),
            Breakpoint::Standard => self.main_areas_standard(header_height),
            Breakpoint::Compact => self.main_areas_compact(header_height),
            Breakpoint::Minimal => self.main_areas_minimal(header_height),
        }
    }

    /// Wide breakpoint: three-pane layout (list + detail + aux).
    fn main_areas_wide(&self, header_height: u16) -> MainAreas {
        let mut constraints = Vec::new();
        if header_height > 0 {
            constraints.push(Constraint::Fixed(header_height));
        }
        constraints.push(Constraint::Fixed(3)); // Search input
        constraints.push(Constraint::Min(10)); // Process table
        constraints.push(Constraint::Fixed(1)); // Status bar

        let v_chunks = Flex::vertical().constraints(constraints).split(self.area);

        let (header, search, content, status) = if header_height > 0 {
            (Some(v_chunks[0]), v_chunks[1], v_chunks[2], v_chunks[3])
        } else {
            (None, v_chunks[0], v_chunks[1], v_chunks[2])
        };

        // Horizontal split of content: list | detail | aux
        let content_chunks = Flex::horizontal()
            .constraints([
                Constraint::Percentage(45.0), // List
                Constraint::Percentage(35.0), // Detail
                Constraint::Percentage(20.0), // Aux
            ])
            .split(content);

        MainAreas {
            header,
            search,
            list: content_chunks[0],
            detail: Some(content_chunks[1]),
            aux: Some(content_chunks[2]),
            status,
        }
    }

    /// Standard breakpoint: list + detail split.
    fn main_areas_standard(&self, header_height: u16) -> MainAreas {
        let mut constraints = Vec::new();
        if header_height > 0 {
            constraints.push(Constraint::Fixed(header_height));
        }
        constraints.push(Constraint::Fixed(3)); // Search input
        constraints.push(Constraint::Min(10)); // Process table
        constraints.push(Constraint::Fixed(1)); // Status bar

        let v_chunks = Flex::vertical().constraints(constraints).split(self.area);

        let (header, search, content, status) = if header_height > 0 {
            (Some(v_chunks[0]), v_chunks[1], v_chunks[2], v_chunks[3])
        } else {
            (None, v_chunks[0], v_chunks[1], v_chunks[2])
        };

        // Horizontal split of content: list | detail
        let content_chunks = Flex::horizontal()
            .constraints([
                Constraint::Percentage(60.0), // List
                Constraint::Percentage(40.0), // Detail
            ])
            .split(content);

        MainAreas {
            header,
            search,
            list: content_chunks[0],
            detail: Some(content_chunks[1]),
            aux: None,
            status,
        }
    }

    /// Compact breakpoint: list + detail with tighter spacing.
    fn main_areas_compact(&self, header_height: u16) -> MainAreas {
        let mut constraints = Vec::new();
        if header_height > 0 {
            constraints.push(Constraint::Fixed(header_height));
        }
        constraints.push(Constraint::Fixed(3)); // Search input
        constraints.push(Constraint::Min(10)); // Process table
        constraints.push(Constraint::Fixed(1)); // Status bar

        let v_chunks = Flex::vertical().constraints(constraints).split(self.area);

        let (header, search, content, status) = if header_height > 0 {
            (Some(v_chunks[0]), v_chunks[1], v_chunks[2], v_chunks[3])
        } else {
            (None, v_chunks[0], v_chunks[1], v_chunks[2])
        };

        let content_chunks = Flex::horizontal()
            .constraints([
                Constraint::Percentage(65.0), // List
                Constraint::Percentage(35.0), // Detail
            ])
            .split(content);

        MainAreas {
            header,
            search,
            list: content_chunks[0],
            detail: Some(content_chunks[1]),
            aux: None,
            status,
        }
    }

    /// Minimal breakpoint: single-pane layout.
    fn main_areas_minimal(&self, header_height: u16) -> MainAreas {
        let mut constraints = Vec::new();
        if header_height > 0 {
            constraints.push(Constraint::Fixed(header_height));
        }
        constraints.push(Constraint::Fixed(1)); // Compact search
        constraints.push(Constraint::Min(5)); // Process list
        constraints.push(Constraint::Fixed(1)); // Status

        let chunks = Flex::vertical().constraints(constraints).split(self.area);

        let (header, search, list, status) = if header_height > 0 {
            (Some(chunks[0]), chunks[1], chunks[2], chunks[3])
        } else {
            (None, chunks[0], chunks[1], chunks[2])
        };

        MainAreas {
            header,
            search,
            list,
            detail: None,
            aux: None,
            status,
        }
    }

    /// Compute evidence detail view areas.
    pub fn detail_areas(&self) -> DetailAreas {
        match self.breakpoint {
            Breakpoint::Standard | Breakpoint::Wide | Breakpoint::Compact => {
                self.detail_areas_standard()
            }
            Breakpoint::Minimal => self.detail_areas_compact(),
        }
    }

    /// Standard detail layout (large/medium).
    fn detail_areas_standard(&self) -> DetailAreas {
        let chunks = Flex::vertical()
            .constraints([
                Constraint::Percentage(30.0), // Process info header
                Constraint::Percentage(50.0), // Evidence ledger
                Constraint::Percentage(20.0), // Actions panel
            ])
            .split(self.area);

        DetailAreas {
            header: chunks[0],
            evidence: chunks[1],
            actions: chunks[2],
        }
    }

    /// Compact detail layout (small).
    fn detail_areas_compact(&self) -> DetailAreas {
        let chunks = Flex::vertical()
            .constraints([
                Constraint::Fixed(4), // Compact header
                Constraint::Min(5),   // Evidence (scrollable)
                Constraint::Fixed(3), // Actions
            ])
            .split(self.area);

        DetailAreas {
            header: chunks[0],
            evidence: chunks[1],
            actions: chunks[2],
        }
    }

    /// Compute galaxy brain view areas.
    pub fn galaxy_brain_areas(&self) -> GalaxyBrainAreas {
        match self.breakpoint {
            Breakpoint::Wide | Breakpoint::Standard => self.galaxy_brain_large(),
            Breakpoint::Compact | Breakpoint::Minimal => self.galaxy_brain_stacked(),
        }
    }

    /// Large breakpoint: side-by-side math and explanation.
    fn galaxy_brain_large(&self) -> GalaxyBrainAreas {
        let chunks = Flex::horizontal()
            .constraints([
                Constraint::Percentage(60.0), // Math display
                Constraint::Percentage(40.0), // Explanation
            ])
            .split(self.area);

        GalaxyBrainAreas {
            math: chunks[0],
            explanation: chunks[1],
        }
    }

    /// Medium/small: stacked layout.
    fn galaxy_brain_stacked(&self) -> GalaxyBrainAreas {
        let chunks = Flex::vertical()
            .constraints([
                Constraint::Percentage(60.0), // Math display
                Constraint::Percentage(40.0), // Explanation
            ])
            .split(self.area);

        GalaxyBrainAreas {
            math: chunks[0],
            explanation: chunks[1],
        }
    }

    /// Compute centered popup/dialog area.
    ///
    /// Returns a centered rectangle suitable for dialogs, constrained
    /// to reasonable proportions based on terminal size.
    pub fn popup_area(&self, width_pct: u16, height_pct: u16) -> Rect {
        let width = (self.area.width as u32 * width_pct as u32 / 100) as u16;
        let height = (self.area.height as u32 * height_pct as u32 / 100) as u16;

        // Apply min/max constraints
        let width = width.max(30).min(self.area.width.saturating_sub(4));
        let height = height.max(10).min(self.area.height.saturating_sub(4));

        let x = (self.area.width.saturating_sub(width)) / 2;
        let y = (self.area.height.saturating_sub(height)) / 2;

        Rect::new(self.area.x + x, self.area.y + y, width, height)
    }
}

// ---------------------------------------------------------------------------
// Layout state tracking
// ---------------------------------------------------------------------------

/// Tracks layout state changes for logging and animations.
#[derive(Debug, Clone)]
pub struct LayoutState {
    /// Previous breakpoint (for transition detection).
    prev_breakpoint: Option<Breakpoint>,
    /// Current breakpoint.
    current_breakpoint: Breakpoint,
    /// Previous terminal size.
    prev_size: (u16, u16),
    /// Current terminal size.
    current_size: (u16, u16),
}

impl LayoutState {
    /// Create new layout state.
    pub fn new(width: u16, height: u16) -> Self {
        let breakpoint = Breakpoint::from_size(width, height);
        Self {
            prev_breakpoint: None,
            current_breakpoint: breakpoint,
            prev_size: (width, height),
            current_size: (width, height),
        }
    }

    /// Update state for new terminal size.
    ///
    /// Returns true if breakpoint changed.
    pub fn update(&mut self, width: u16, height: u16) -> bool {
        let new_breakpoint = Breakpoint::from_size(width, height);
        let changed = new_breakpoint != self.current_breakpoint;

        if changed {
            debug!(
                from = self.current_breakpoint.name(),
                to = new_breakpoint.name(),
                "layout.breakpoint_change"
            );
        }

        if self.current_size != (width, height) {
            debug!(
                old_width = self.current_size.0,
                old_height = self.current_size.1,
                new_width = width,
                new_height = height,
                new_breakpoint = new_breakpoint.name(),
                "layout.resize"
            );
        }

        self.prev_breakpoint = Some(self.current_breakpoint);
        self.current_breakpoint = new_breakpoint;
        self.prev_size = self.current_size;
        self.current_size = (width, height);

        changed
    }

    /// Get the current breakpoint.
    pub fn breakpoint(&self) -> Breakpoint {
        self.current_breakpoint
    }

    /// Check if we just transitioned breakpoints.
    pub fn did_breakpoint_change(&self) -> bool {
        self.prev_breakpoint
            .map(|prev| prev != self.current_breakpoint)
            .unwrap_or(false)
    }

    /// Get current terminal size.
    pub fn size(&self) -> (u16, u16) {
        self.current_size
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breakpoint_detection() {
        assert_eq!(Breakpoint::from_size(60, 24), Breakpoint::Minimal);
        assert_eq!(Breakpoint::from_size(80, 24), Breakpoint::Compact);
        assert_eq!(Breakpoint::from_size(100, 40), Breakpoint::Compact);
        assert_eq!(Breakpoint::from_size(120, 40), Breakpoint::Standard);
        assert_eq!(Breakpoint::from_size(200, 60), Breakpoint::Wide);
    }

    #[test]
    fn test_breakpoint_boundaries() {
        assert_eq!(Breakpoint::from_size(79, 24), Breakpoint::Minimal);
        assert_eq!(Breakpoint::from_size(80, 24), Breakpoint::Compact);
        assert_eq!(Breakpoint::from_size(119, 24), Breakpoint::Compact);
        assert_eq!(Breakpoint::from_size(120, 24), Breakpoint::Standard);
        assert_eq!(Breakpoint::from_size(199, 24), Breakpoint::Standard);
        assert_eq!(Breakpoint::from_size(200, 24), Breakpoint::Wide);
    }

    #[test]
    fn test_layout_main_areas_wide() {
        let area = Rect::new(0, 0, 220, 60);
        let layout = ResponsiveLayout::new(area);

        assert_eq!(layout.breakpoint(), Breakpoint::Wide);

        let areas = layout.main_areas();
        assert!(areas.detail.is_some());
        assert!(areas.aux.is_some());

        // Aux should be ~20% of 220 = 44
        let aux = areas.aux.unwrap();
        assert_eq!(aux.width, 44);

        // Status bar should be 1 row at bottom
        assert_eq!(areas.status.height, 1);
        assert_eq!(areas.status.y + areas.status.height, area.height);
    }

    #[test]
    fn test_layout_main_areas_standard() {
        let area = Rect::new(0, 0, 140, 40);
        let layout = ResponsiveLayout::new(area);

        assert_eq!(layout.breakpoint(), Breakpoint::Standard);

        let areas = layout.main_areas();
        assert!(areas.detail.is_some());
        assert!(areas.aux.is_none());

        // Search should be 3 rows
        assert_eq!(areas.search.height, 3);

        // Status bar should be 1 row
        assert_eq!(areas.status.height, 1);
    }

    #[test]
    fn test_layout_main_areas_compact() {
        let area = Rect::new(0, 0, 100, 40);
        let layout = ResponsiveLayout::new(area);

        assert_eq!(layout.breakpoint(), Breakpoint::Compact);

        let areas = layout.main_areas();
        assert!(areas.detail.is_some());
        assert!(areas.aux.is_none());

        // Search should be 3 rows
        assert_eq!(areas.search.height, 3);
    }

    #[test]
    fn test_layout_main_areas_with_header_wide_uses_content_row() {
        let area = Rect::new(0, 0, 220, 60);
        let layout = ResponsiveLayout::new(area);
        let areas = layout.main_areas_with_header(2);

        assert_eq!(areas.header.unwrap().height, 2);
        assert_eq!(areas.search.height, 3);
        assert_eq!(areas.status.height, 1);
        assert!(
            areas.list.height > areas.search.height,
            "list/detail panes should use main content row, not search row"
        );
        assert_eq!(areas.list.y, areas.search.y + areas.search.height);
    }

    #[test]
    fn test_layout_main_areas_with_header_standard_uses_content_row() {
        let area = Rect::new(0, 0, 140, 40);
        let layout = ResponsiveLayout::new(area);
        let areas = layout.main_areas_with_header(2);

        assert_eq!(areas.header.unwrap().height, 2);
        assert_eq!(areas.search.height, 3);
        assert!(areas.detail.is_some());
        assert!(
            areas.list.height > areas.search.height,
            "list/detail panes should use main content row, not search row"
        );
        assert_eq!(areas.list.y, areas.search.y + areas.search.height);
    }

    #[test]
    fn test_layout_main_areas_with_header_compact_uses_content_row() {
        let area = Rect::new(0, 0, 100, 40);
        let layout = ResponsiveLayout::new(area);
        let areas = layout.main_areas_with_header(2);

        assert_eq!(areas.header.unwrap().height, 2);
        assert_eq!(areas.search.height, 3);
        assert!(areas.detail.is_some());
        assert!(
            areas.list.height > areas.search.height,
            "list/detail panes should use main content row, not search row"
        );
        assert_eq!(areas.list.y, areas.search.y + areas.search.height);
    }

    #[test]
    fn test_layout_main_areas_minimal() {
        let area = Rect::new(0, 0, 60, 20);
        let layout = ResponsiveLayout::new(area);

        assert_eq!(layout.breakpoint(), Breakpoint::Minimal);

        let areas = layout.main_areas();
        assert!(areas.detail.is_none());

        // Compact search should be 1 row
        assert_eq!(areas.search.height, 1);
    }

    #[test]
    fn test_layout_too_small() {
        let tiny = Rect::new(0, 0, 30, 8);
        let layout = ResponsiveLayout::new(tiny);
        assert!(layout.is_too_small());

        let ok = Rect::new(0, 0, 60, 20);
        let layout = ResponsiveLayout::new(ok);
        assert!(!layout.is_too_small());
    }

    #[test]
    fn test_popup_area_centered() {
        let area = Rect::new(0, 0, 100, 40);
        let layout = ResponsiveLayout::new(area);

        let popup = layout.popup_area(50, 50);

        // Should be roughly centered
        assert!(popup.x > 0);
        assert!(popup.y > 0);
        assert!(popup.x + popup.width <= area.width);
        assert!(popup.y + popup.height <= area.height);
    }

    #[test]
    fn test_layout_state_tracking() {
        let mut state = LayoutState::new(100, 40);
        assert_eq!(state.breakpoint(), Breakpoint::Compact);

        // Same breakpoint
        let changed = state.update(110, 40);
        assert!(!changed);
        assert!(!state.did_breakpoint_change());

        // Different breakpoint
        let changed = state.update(60, 20);
        assert!(changed);
        assert!(state.did_breakpoint_change());
        assert_eq!(state.breakpoint(), Breakpoint::Minimal);
    }

    #[test]
    fn test_detail_areas() {
        let large = ResponsiveLayout::new(Rect::new(0, 0, 200, 60));
        let detail = large.detail_areas();
        assert!(detail.header.height > 0);
        assert!(detail.evidence.height > detail.header.height);

        let small = ResponsiveLayout::new(Rect::new(0, 0, 60, 20));
        let detail = small.detail_areas();
        assert_eq!(detail.header.height, 4); // Compact header
    }

    #[test]
    fn test_galaxy_brain_areas() {
        let large = ResponsiveLayout::new(Rect::new(0, 0, 200, 60));
        let gb = large.galaxy_brain_areas();
        // Large: side-by-side (horizontal)
        assert!(gb.math.width > gb.explanation.width);

        let medium = ResponsiveLayout::new(Rect::new(0, 0, 100, 40));
        let gb = medium.galaxy_brain_areas();
        // Medium: stacked (vertical)
        assert!(gb.math.height > gb.explanation.height);
    }

    #[test]
    fn test_areas_cover_full_width() {
        // Verify no gaps in horizontal splits
        let area = Rect::new(0, 0, 220, 60);
        let layout = ResponsiveLayout::new(area);
        let areas = layout.main_areas();

        let list_w = areas.list.width;
        let detail_w = areas.detail.unwrap().width;
        let aux_w = areas.aux.unwrap().width;
        assert_eq!(
            list_w + detail_w + aux_w,
            area.width,
            "panes should cover full width"
        );
    }

    #[test]
    fn test_areas_cover_full_height() {
        // Verify no gaps in vertical splits
        let area = Rect::new(0, 0, 140, 40);
        let layout = ResponsiveLayout::new(area);
        let areas = layout.main_areas();

        let total_h = areas.search.height + areas.list.height + areas.status.height;
        assert_eq!(total_h, area.height, "rows should cover full height");
    }
}
