//! Correlates VPN activity for a user
//!
//! This app takes a user name and pulls VPN logs and then looks for correlations between MAC
//! address and source IP.  The first login will always show red as there is no previous login to
//! correlate with.
use egui::RichText;

use crate::{store::Store, user::vpnlog::VpnLog};
use std::rc::Rc;

use super::color;

pub struct Visor {
    store: Rc<Store>,
    user: String,
    vpn_logs: Vec<VpnLog>,
    vpn_rx: Option<std::thread::JoinHandle<Option<Vec<VpnLog>>>>,
    failed: bool,
}

impl Visor {
    pub fn new(store: Rc<Store>) -> Self {
        Self {
            store,
            user: String::new(),
            vpn_logs: vec![],
            vpn_rx: None,
            failed: false,
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        egui_extras::StripBuilder::new(ui)
            .size(egui_extras::Size::exact(20.0))
            .size(egui_extras::Size::remainder())
            .vertical(|mut strip| {
                strip.cell(|ui| {
                    ui.horizontal(|ui| {
                        ui.label("User");
                        let enabled = self.vpn_rx.is_none();
                        ui.add_enabled_ui(enabled, |ui| {
                            ui.text_edit_singleline(&mut self.user);
                            if ui.button("Pull vpn activity").clicked() {
                                self.vpn_rx = Some(self.store.run_visor(self.user.to_string()));
                            }
                        });
                        if !enabled {
                            ui.spinner();
                        }
                        if self.failed {
                            ui.label(RichText::new("Lookup failed").color(color::ROSE));
                        }
                    });
                });
                strip.cell(|ui| {
                    if let Some(vpn_rx) = &self.vpn_rx {
                        ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Wait);
                        if vpn_rx.is_finished() {
                            let logs = self
                                .vpn_rx
                                .take()
                                .expect("Failed to take vpn_rx from Visor")
                                .join()
                                .expect("Couldn't get logs from thread");
                            match logs {
                                Some(logs) => self.vpn_logs = logs,
                                None => self.failed = true,
                            }
                            ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Default);
                            self.vpn_rx = None;
                        }
                    } else if !self.vpn_logs.is_empty() {
                        self.table(ui);
                    } else {
                        ui.label("No logs to show");
                    }
                });
            });
    }

    fn table(&mut self, ui: &mut egui::Ui) {
        egui_extras::TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .columns(egui_extras::Column::auto(), 4)
            .column(egui_extras::Column::remainder())
            .header(20.0, |mut header| {
                header.col(|ui| {
                    ui.label("Time").on_hover_ui(|ui| {
                        ui.label(
                            RichText::new("Green for correlation with last log").color(color::FOAM),
                        );
                        ui.label(RichText::new("Red for no correlation").color(color::LOVE));
                    });
                });
                header.col(|ui| {
                    ui.label("Source IP");
                });
                header.col(|ui| {
                    ui.label("MAC");
                });
                header.col(|ui| {
                    ui.label("Platform");
                });
                header.col(|ui| {
                    ui.label("Location");
                });
            })
            .body(|body| {
                body.rows(20.0, self.vpn_logs.len(), |i, mut row| {
                    let log = &self.vpn_logs[i];
                    row.col(|ui| {
                        ui.label(RichText::new(log.time.format("%T %D").to_string()).color(
                            if log.correlate_prev {
                                color::FOAM
                            } else {
                                color::LOVE
                            },
                        ));
                    });

                    row.col(|ui| {
                        let lable = ui
                            .add(
                                egui::Label::new(RichText::new(log.source_ip.to_string()).color(
                                    if log.is_relay {
                                        color::ROSE
                                    } else {
                                        color::TEXT
                                    },
                                ))
                                .sense(egui::Sense::click()),
                            )
                            .context_menu(|ui| {
                                if let Some(ipinfo) = self.store.get_ipthreat(log.source_ip) {
                                    if ipinfo.vibe_check() {
                                        ui.label("Nothing funky");
                                    } else {
                                        ui.vertical(|ui| {
                                            if ipinfo.is_tor {
                                                ui.label("✅Tor");
                                            }

                                            if ipinfo.is_icloud_relay {
                                                ui.label("✅iCloud Relay");
                                            }

                                            if ipinfo.is_proxy {
                                                ui.label("✅Proxy");
                                            }

                                            if ipinfo.is_datacenter {
                                                ui.label("✅Datacenter");
                                            }

                                            if ipinfo.is_anonymous {
                                                ui.label("✅Anonymous");
                                            }

                                            if ipinfo.is_known_attacker {
                                                ui.label("✅Known Attacker");
                                            }

                                            if ipinfo.is_known_abuser {
                                                ui.label("✅Known Abuser");
                                            }

                                            if ipinfo.is_threat {
                                                ui.label("✅Threat");
                                            }

                                            if ipinfo.is_bogon {
                                                ui.label("✅Bogon");
                                            }

                                            if !ipinfo.blocklists.is_empty() {
                                                ui.label("✅Blocklists");
                                            }
                                        });
                                    }
                                } else {
                                    ui.label(
                                        RichText::new("Could not fetch IP info").color(color::ROSE),
                                    );
                                }
                            });
                        if lable.clicked() {
                            ui.output_mut(|o| o.copied_text = log.source_ip.to_string());
                        }
                    });

                    row.col(|ui| {
                        ui.label(log.dev_mac.as_ref().unwrap_or(&"".to_string()));
                    });

                    row.col(|ui| {
                        ui.label(&log.dev_platform);
                    });

                    row.col(|ui| {
                        ui.label(log.format_location().unwrap_or_default());
                    });
                });
            });
    }
}

impl super::panels::Panel for Visor {
    fn name(&self) -> &'static str {
        "🕶 Visor"
    }

    fn show(&mut self, ctx: &egui::Context, open: &mut bool) {
        egui::Window::new(
            RichText::new(format!("{}: Your Grandmother's VPN Multi", self.name()))
                .color(color::GOLD),
        )
        .open(open)
        .vscroll(false)
        .resizable(true)
        .default_size(egui::vec2(500.0, 300.0))
        .show(ctx, |ui| {
            self.ui(ui);

            if ui.ui_contains_pointer() && !ctx.wants_keyboard_input() {
                ctx.input(|i| {
                    if i.key_pressed(egui::Key::Enter) && self.vpn_rx.is_none() {
                        self.vpn_rx = Some(self.store.run_visor(self.user.to_string()));
                    }
                });
            }
        });

        if self.vpn_rx.is_some() {
            std::thread::sleep(std::time::Duration::from_millis(10));
            ctx.request_repaint(); // Call repaint to re-check if the thread is finished
        }
    }

    fn desc(&self) -> &'static str {
        "VPN multi"
    }
}
