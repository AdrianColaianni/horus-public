//! Composes the UI
//!
//! Each module is a different app or state. To make things clear, apps are the tools that comprise
//! HOURS, such as Duplex and Sonar. States are the UIs that lead to the MainUi where the apps are
//! visible, this includes login and main.

mod color;
mod duplex;
pub mod login;
pub mod main;
mod panels;
mod simplex;
pub mod sonar;
mod visor;
mod zeppelin;
use crate::store::Store;
use log::info;

/// This enum is how states communciate between each other.  For example, when you click the login
/// button, the login state will do some basic checks and then return a StateUIAction::Login which
/// will tell the StateUI to switch to the main state.
pub enum StateUIAction {
    Login { store: Store },
    None,
}

/// Holds the main state of HORUS
pub struct StateUI {
    panel: Box<dyn StateUIVariant>,
}

/// Any state must imply this trait to be a main state of HORUS
pub trait StateUIVariant {
    fn update_panel(&mut self, ctx: &egui::Context) -> StateUIAction;
}

#[allow(clippy::derivable_impls)]
impl Default for StateUI {
    fn default() -> Self {
        Self {
            panel: Box::<login::LoginUI>::default(),
        }
    }
}

impl eframe::App for StateUI {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let visuals = egui::Visuals {
            override_text_color: None,
            hyperlink_color: color::IRIS,
            faint_bg_color: color::SURFACE, // Table stripes
            extreme_bg_color: color::HIGHLIGHT_LOW,
            code_bg_color: color::HIGHLIGHT_MED,
            warn_fg_color: color::GOLD,
            error_fg_color: color::LOVE,
            window_fill: color::OVERLAY, // Widget background
            panel_fill: color::BASE,     // Background background
            widgets: egui::style::Widgets {
                noninteractive: egui::style::WidgetVisuals {
                    bg_fill: color::SURFACE,
                    weak_bg_fill: color::SURFACE,
                    bg_stroke: egui::Stroke::new(1.0, color::HIGHLIGHT_MED), // Separator color
                    rounding: egui::Rounding::same(4.0),
                    fg_stroke: egui::Stroke::new(1.0, color::TEXT),
                    expansion: 1.0,
                },
                inactive: egui::style::WidgetVisuals {
                    bg_fill: color::MUTED,
                    weak_bg_fill: color::MUTED,
                    bg_stroke: egui::Stroke::new(1.0, color::OVERLAY),
                    rounding: egui::Rounding::same(4.0),
                    fg_stroke: egui::Stroke::new(1.0, color::TEXT),
                    expansion: 1.0,
                },
                hovered: egui::style::WidgetVisuals {
                    bg_fill: color::MUTED,
                    weak_bg_fill: color::MUTED,
                    bg_stroke: egui::Stroke::new(1.0, color::MUTED),
                    rounding: egui::Rounding::same(4.0),
                    fg_stroke: egui::Stroke::new(1.0, color::TEXT),
                    expansion: 1.0,
                },
                active: egui::style::WidgetVisuals {
                    bg_fill: color::SUBTLE,
                    weak_bg_fill: color::SUBTLE,
                    bg_stroke: egui::Stroke::new(1.0, color::SUBTLE),
                    rounding: egui::Rounding::same(4.0),
                    fg_stroke: egui::Stroke::new(1.0, color::TEXT),
                    expansion: 1.0,
                },
                open: egui::style::WidgetVisuals {
                    bg_fill: color::SUBTLE,
                    weak_bg_fill: color::SUBTLE,
                    bg_stroke: egui::Stroke::new(1.0, color::MUTED),
                    rounding: egui::Rounding::same(4.0),
                    fg_stroke: egui::Stroke::new(1.0, color::TEXT),
                    expansion: 1.0,
                },
            },
            selection: egui::style::Selection {
                bg_fill: color::PINE,
                stroke: egui::Stroke::new(1.0, color::TEXT),
            },
            ..ctx.style().visuals.clone()
        };
        ctx.set_visuals(visuals);
        let resp = self.panel.update_panel(ctx);

        match resp {
            StateUIAction::Login { store } => {
                info!("Swiching to loading screen");
                self.panel = Box::new(main::MainUI::new(store));
            }
            StateUIAction::None => (),
        }
    }
}

/// This draws a shadow behind a panel and is used by the loginUI
pub fn shadow_background(
    painter: &egui::Painter,
    paint_rect: egui::Rect,
    fill: egui::Color32,
    stroke: egui::Stroke,
    corner_radius: f32,
    shadow: egui::epaint::Shadow,
) {
    let frame_shape = egui::Shape::Rect(egui::epaint::RectShape {
        rect: paint_rect,
        rounding: egui::Rounding::same(10.0),
        fill,
        stroke,
    });

    let shadow = shadow.tessellate(paint_rect, corner_radius);
    let shadow = egui::Shape::Mesh(shadow);
    let shape = egui::Shape::Vec(vec![shadow, frame_shape]);
    painter.add(shape);
}
