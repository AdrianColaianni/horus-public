//! Duplex but for one user
//!
//! This app shows the Duo logs of a single user.
use super::color;
use crate::{
    store::Store,
    user::{
        login::{Integration, LoginResult, Reason},
        User,
    },
};
use egui::{Label, RichText};
use std::{rc::Rc, thread::JoinHandle};

pub struct Simplex {
    days: i64,
    pull_user: Option<JoinHandle<Option<User>>>,
    store: Rc<Store>,
    user: Option<User>,
    user_name: String,
}

impl Simplex {
    pub fn new(store: Rc<Store>) -> Self {
        Self {
            user: None,
            user_name: String::new(),
            store,
            pull_user: None,
            days: 14,
        }
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.horizontal(|ui| {
                ui.heading("User");
                let enabled = self.pull_user.is_none();
                ui.add_enabled_ui(enabled, |ui| {
                    ui.text_edit_singleline(&mut self.user_name);
                    ui.add(egui::Slider::new(&mut self.days, 7..=90).text("days"));

                    if ui.button("Pull logs").clicked() {
                        ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Progress);
                        self.pull_user =
                            Some(self.store.run_simplex(self.user_name.to_owned(), self.days));
                    }
                });
                if !enabled {
                    ui.spinner();
                }
            });
        });
    }

    fn hdtools_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let user = &self.user.as_ref().expect("Simplex failed to get user");
            if user.creation_date.is_some() || user.location.is_some() {
                if let Some(cd) = &user.creation_date {
                    ui.label(format!("Created {}", cd.format("%m/%d/%Y")));
                    ui.separator();
                }
                if let Some(loc) = &user.location {
                    ui.label(loc.to_string());
                }
            } else {
                ui.label(RichText::new("No HDTools info").color(color::ROSE));
            }
        });
    }

    fn table(&mut self, ui: &mut egui::Ui) {
        ui.separator();

        let table = egui_extras::TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .columns(egui_extras::Column::auto(), 6)
            .column(egui_extras::Column::remainder());
        let user = &self.user.as_ref().expect("Simplex failed to get user");
        table
            .header(20.0, |mut header| {
                header.col(|ui| {
                    ui.label("Time")
                        .on_hover_text("Right click for Cherwell templates");
                });
                header.col(|ui| {
                    ui.label("Result");
                });
                header.col(|ui| {
                    ui.label("Reason").on_hover_text("Hehe monkey");
                });
                header.col(|ui| {
                    ui.label("Factor");
                });
                header.col(|ui| {
                    ui.label("Integration");
                });
                header.col(|ui| {
                    ui.label("IP").on_hover_ui(|ui| {
                        ui.label(
                            "Left click to copy to clipboard\nRight click to view service details",
                        );
                        ui.label(RichText::new("- Green for CUVPN IP").color(color::FOAM));
                        ui.label(RichText::new("- Orange for known proxy").color(color::ROSE));
                    });
                });
                header.col(|ui| {
                    ui.label("Location").on_hover_text(
                        "Left click to copy to clipboard\nRight click to copy coordinates",
                    );
                });
            })
            .body(|body| {
                body.rows(20.0, user.logins.len(), |i, mut row| {
                    let login = &user.logins[i];
                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(format!("{}", login.time.format("%T %D")))
                                .sense(egui::Sense::click()),
                        )
                        .context_menu(|ui| {
                            if ui.button("Copy username").clicked() {
                                ui.output_mut(|o| o.copied_text = login.user.to_owned());
                            }
                            if ui.button("Copy short description").clicked() {
                                ui.output_mut(|o| {
                                    o.copied_text = "Duo Multi Login Suspicious Activity".to_owned()
                                });
                            }
                            let analyst_name = self.store.analyst_name();
                            if !analyst_name.is_empty() && ui.button("Copy first contact").clicked()
                            {
                                ui.output_mut(|o| {
                                    if login.result == LoginResult::Fraud {
                                        o.copied_text = format!(
                                            std::include_str!(
                                                "../../templates/first_contact_fraud.txt"
                                            ),
                                            analyst_name,
                                            login.time.format("%m/%d"),
                                            login.time.format("%I:%M %p"),
                                            login.factor,
                                            login
                                                .format_location()
                                                .unwrap_or_else(|| "CUVPN".to_owned()),
                                            analyst_name
                                        )
                                    } else {
                                        o.copied_text = format!(
                                            std::include_str!("../../templates/first_contact.txt"),
                                            analyst_name,
                                            login.time.format("%m/%d"),
                                            login.time.format("%I:%M %p"),
                                            login.factor,
                                            login
                                                .format_location()
                                                .unwrap_or_else(|| "CUVPN".to_owned()),
                                            analyst_name
                                        )
                                    }
                                });
                            }
                            if ui.button("Copy password reset").clicked() {
                                ui.output_mut(|o| {
                                    o.copied_text = format!(
                                        std::include_str!("../../templates/password_reset.txt"),
                                        analyst_name, analyst_name,
                                    )
                                });
                            }
                            if ui.button("Copy service class").clicked() {
                                ui.output_mut(|o| {
                                    o.copied_text =
                                        "security incident response and investigation".to_owned();
                                });
                                ui.close_menu();
                            }
                        });
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(login.result.to_string()).color(
                            match login.result {
                                LoginResult::Failure => color::ROSE,
                                LoginResult::Fraud => color::LOVE,
                                _ => color::TEXT,
                            },
                        ));
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(login.reason.to_string()).color(
                            match login.reason {
                                Reason::DenyUnenrolledUser => color::ROSE,
                                _ => color::TEXT,
                            },
                        ));
                    });
                    row.col(|ui| {
                        ui.label(login.factor.to_string());
                    });
                    row.col(|ui| {
                        ui.label(RichText::new(login.integration.to_string()).color(
                            match login.integration {
                                Integration::CuVpn => color::FOAM,
                                Integration::Citrix => color::FOAM,
                                Integration::Dmp => color::LOVE,
                                _ => color::TEXT,
                            },
                        ));
                    });
                    row.col(|ui| {
                        if let Some(ip) = login.ip {
                            let lable = ui
                                .add(
                                    Label::new(RichText::new(ip.to_string()).color(
                                        if login.is_vpn_ip() {
                                            color::FOAM
                                        } else if login.is_relay {
                                            color::ROSE
                                        } else {
                                            color::TEXT
                                        },
                                    ))
                                    .sense(egui::Sense::click()),
                                )
                                .on_hover_text(login.asn.as_deref().unwrap_or_default())
                                .context_menu(|ui| {
                                    if let Some(ipinfo) = self.store.get_ipthreat(ip) {
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
                                            RichText::new("Could not fetch IP info")
                                                .color(color::ROSE),
                                        );
                                    }
                                });
                            if lable.clicked() {
                                ui.output_mut(|o| o.copied_text = ip.to_string());
                            }
                        }
                    });
                    row.col(|ui| {
                        if let Some(loc) = login.format_location() {
                            let label =
                                ui.add(Label::new(loc.as_str()).sense(egui::Sense::click()));
                            if label.clicked() {
                                ui.output_mut(|o| o.copied_text = loc);
                            }
                            if label.secondary_clicked() {
                                ui.output_mut(|o| {
                                    o.copied_text = login
                                        .location
                                        .map(|l| format!("{}, {}", l.0, l.1))
                                        .unwrap_or_default()
                                });
                            }
                        }
                    });
                });
            });
    }

    fn ui(&mut self, ui: &mut egui::Ui) {
        egui_extras::StripBuilder::new(ui)
            .sizes(egui_extras::Size::exact(20.0), 2)
            .size(egui_extras::Size::remainder().at_least(100.0))
            .vertical(|mut strip| {
                strip.cell(|ui| self.top_bar(ui));
                if self.user.is_some() {
                    strip.cell(|ui| self.hdtools_bar(ui));
                    strip.cell(|ui| self.table(ui));
                }
            });
    }
}

impl super::panels::Panel for Simplex {
    fn name(&self) -> &'static str {
        "☎ Simplex"
    }

    fn show(&mut self, ctx: &egui::Context, open: &mut bool) {
        if let Some(pull_user) = &self.pull_user {
            if pull_user.is_finished() {
                if let Some(rx) = self.pull_user.take() {
                    if let Some(l) = rx.join().expect("Couldn't get more logs from thread") {
                        self.user = Some(l);
                    }
                }
                self.pull_user = None;
            } else {
                std::thread::sleep(std::time::Duration::from_millis(10));
                ctx.request_repaint(); // Call repaint to re-check if the thread is finished
            }
        }

        egui::Window::new(
            RichText::new(format!("{}: Just a Few Beers Please", self.name())).color(color::GOLD),
        )
        .open(open)
        .default_size(egui::vec2(800.0, 600.0))
        .vscroll(false)
        .show(ctx, |ui| {
            if self.pull_user.is_some() {
                ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Progress);
            }
            self.ui(ui);

            if ui.ui_contains_pointer() && !ctx.wants_keyboard_input() {
                ctx.input(|o| {
                    if o.key_pressed(egui::Key::Enter) && self.pull_user.is_none() {
                        self.pull_user =
                            Some(self.store.run_simplex(self.user_name.to_owned(), self.days));
                    }
                });
            }
        });
    }

    fn desc(&self) -> &'static str {
        "Lookup single user"
    }
}
