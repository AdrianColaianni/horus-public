//! Find IP/MAC/User
//!
//! This app queies the splunk `splunk_network_cisco` and `splunk_network_ise` indexes for IP/MAC/User
//! of a specified IP/MAC/User.
use std::{net::Ipv4Addr, rc::Rc};

use egui::{Label, RichText};

use crate::store::Store;

use super::color;

pub struct Sonar {
    store: Rc<Store>,
    lookup: String,
    details: std::sync::Arc<std::sync::RwLock<Details>>,
}

impl Sonar {
    pub fn new(store: Rc<Store>) -> Self {
        Self {
            store,
            lookup: String::default(),
            details: std::sync::Arc::new(std::sync::RwLock::new(Details::default())),
        }
    }
}

impl super::panels::Panel for Sonar {
    fn name(&self) -> &'static str {
        "🔘 Sonar"
    }

    fn desc(&self) -> &'static str {
        "Find IP/MAC/User"
    }

    fn show(&mut self, ctx: &egui::Context, open: &mut bool) {
        egui::Window::new(
            RichText::new(format!("{}: I'm up in yo crib dawg", self.name())).color(color::GOLD),
        )
        .open(open)
        .vscroll(false)
        .resizable(true)
        .fixed_size(egui::vec2(200.0, 100.0))
        .show(ctx, |ui| {
            self.ui(ui);
            if ui.ui_contains_pointer() && !ctx.wants_keyboard_input() {
                ctx.input(|o| {
                    if o.key_pressed(egui::Key::Enter) {
                        self.details
                            .write()
                            .expect("Failed to get write lock on details")
                            .clear();
                        self.store.run_sonar(self.lookup.to_string(), &self.details);
                    }
                });
            }
        });

        if self
            .details
            .read()
            .expect("Failed to get read lock on details")
            .running
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
            ctx.request_repaint(); // Call repaint to re-check if the thread is finished
        }
    }
}

impl Sonar {
    fn ui(&mut self, ui: &mut egui::Ui) {
        egui_extras::StripBuilder::new(ui)
            .size(egui_extras::Size::exact(20.0))
            .size(egui_extras::Size::remainder())
            .vertical(|mut strip| {
                strip.cell(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("IP/MAC/User");
                        let enabled = !self
                            .details
                            .read()
                            .expect("Failed to get read lock on details")
                            .running;
                        ui.add_enabled_ui(enabled, |ui| {
                            ui.text_edit_singleline(&mut self.lookup);
                            if ui.button("Pull details").clicked() {
                                self.details
                                    .write()
                                    .expect("Failed to get write lock on details")
                                    .clear();
                                self.store.run_sonar(self.lookup.to_string(), &self.details);
                            }
                        });
                        if !enabled {
                            ui.spinner();
                        }
                    });
                });
                strip.cell(|ui| {
                    self.grid(ui);
                });
            });
    }

    fn grid(&self, ui: &mut egui::Ui) {
        egui::Grid::new("sonar_grid").show(ui, |ui| {
            let details = self
                .details
                .read()
                .expect("Failed to get read lock on details");
            if details.running {
                ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Wait);
            }
            ui.label("IP");
            let ip = ui.add(
                Label::new(
                    details
                        .ips
                        .iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<String>>()
                        .join(", "),
                )
                .sense(egui::Sense::click()),
            );
            if ip.clicked() {
                ui.output_mut(|o| {
                    o.copied_text = details
                        .ips
                        .first()
                        .map(|ip| ip.to_string())
                        .unwrap_or_default()
                });
            }
            ui.end_row();

            ui.label("MAC");
            let mac = ui.add(Label::new(details.macs.join(", ")).sense(egui::Sense::click()));
            if mac.clicked() {
                ui.output_mut(|o| {
                    o.copied_text = details.macs.first().cloned().unwrap_or_default()
                });
            }
            ui.end_row();

            ui.label("User");
            let user = ui.add(
                Label::new(details.user.as_deref().unwrap_or_default().to_string())
                    .sense(egui::Sense::click()),
            );
            if user.clicked() {
                ui.output_mut(|o| {
                    o.copied_text = details.user.as_deref().unwrap_or_default().to_string()
                });
            }
            ui.end_row();
        });
    }
}

#[derive(Default)]
pub struct Details {
    pub ips: Vec<Ipv4Addr>,
    pub macs: Vec<String>,
    pub user: Option<String>,
    pub running: bool,
}

impl Details {
    pub fn clear(&mut self) {
        self.ips.clear();
        self.macs.clear();
        self.user = None;
        self.running = false;
    }
}
