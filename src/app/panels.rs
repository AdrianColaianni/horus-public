//! Holds HORUS's apps
//!
//! Each app must implement the Panel trait and be included in the panels vector to show in the
//! MainUI.
use std::{collections::BTreeSet, rc::Rc};

use crate::store::Store;

/// Implemented by apps
pub trait Panel {
    /// Returns the name of the app
    fn name(&self) -> &'static str;
    /// Returns the description of the app to be used in the context menu when hovering over the app's button
    fn desc(&self) -> &'static str;
    /// Shows the app
    fn show(&mut self, ctx: &egui::Context, open: &mut bool);
}

pub struct Panels {
    /// Vecor of apps
    panels: Vec<Box<dyn Panel>>,
    /// Defines which apps are open
    open: BTreeSet<String>,
}

impl Panels {
    /// Creates a new Panels struct and defines what apps are available
    pub fn new(store: Rc<Store>) -> Self {
        let panels: Vec<Box<dyn Panel>> = vec![
            Box::new(super::duplex::Duplex::new(Rc::clone(&store))),
            Box::new(super::simplex::Simplex::new(Rc::clone(&store))),
            Box::new(super::visor::Visor::new(Rc::clone(&store))),
            Box::new(super::sonar::Sonar::new(Rc::clone(&store))),
            Box::new(super::zeppelin::Zeppelin::new(Rc::clone(&store))),
        ];
        let open = BTreeSet::new();

        Self { panels, open }
    }

    /// Shows the buttons on the right side
    pub fn checkboxes(&mut self, ui: &mut egui::Ui) {
        let Self { panels, open } = self;
        for panel in panels {
            let mut is_open = open.contains(panel.name());
            ui.toggle_value(&mut is_open, panel.name())
                .on_hover_text(panel.desc());
            set_open(open, panel.name(), is_open);
        }
    }

    /// Shows open apps
    pub fn windows(&mut self, ctx: &egui::Context) {
        let Self { panels, open } = self;
        for panel in panels {
            let mut is_open = open.contains(panel.name());
            panel.show(ctx, &mut is_open);
            set_open(open, panel.name(), is_open);
        }
    }
}

/// Sets whether an app is open
fn set_open(open: &mut BTreeSet<String>, key: &'static str, is_open: bool) {
    if is_open {
        if !open.contains(key) {
            open.insert(key.to_owned());
        }
    } else {
        open.remove(key);
    }
}
