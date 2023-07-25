//! UI for Duplex
use crate::{
    app::color,
    queries::{osiris, splunk::TimeSpan},
    store::Store,
    user::{
        login::{Integration, Login, LoginResult, Reason},
        User,
    },
};
use chrono::{NaiveDate, Timelike};
use egui::{Key, Label, ProgressBar, RichText, TextEdit};
use egui_extras::{Column, DatePickerButton, Size, StripBuilder, TableBuilder};
use std::{rc::Rc, thread::JoinHandle};

trait View {
    fn ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) -> DuplexAction;
    fn store(&self) -> &Rc<Store>;
}

pub struct Duplex {
    panel: Box<dyn View>,
}

impl Duplex {
    pub fn new(store: Rc<Store>) -> Self {
        Self {
            panel: Box::new(DateSelectUi::new(store)),
        }
    }
}

impl super::panels::Panel for Duplex {
    fn name(&self) -> &'static str {
        "📱Duplex"
    }

    fn show(&mut self, ctx: &egui::Context, open: &mut bool) {
        egui::Window::new(
            RichText::new(format!("{}: Don't Drink and Duplex", self.name())).color(color::GOLD),
        )
        .open(open)
        .default_size(egui::vec2(800.0, 600.0))
        .vscroll(false)
        .show(ctx, |ui| {
            let resp = self.panel.ui(ui, ctx);

            match resp {
                DuplexAction::None => (),
                DuplexAction::Query { store, user_range } => {
                    log::info!("Switching to loading screen");
                    let run = store.run_duplex(user_range, chrono::Duration::days(7).into());
                    self.panel = Box::new(LoadingUi::new(store, run));
                }
                DuplexAction::Start { store, users } => {
                    self.panel = Box::new(MainUi::new(store, users));
                }
                DuplexAction::Done {
                    store,
                    investigations,
                } => {
                    self.panel = Box::new(DoneUi::new(store, investigations));
                }
                DuplexAction::Reset => {
                    let store = self.panel.store();

                    self.panel = Box::new(DateSelectUi::new(Rc::clone(store)));
                }
            }
        });
    }

    fn desc(&self) -> &'static str {
        "Duo Multi and Duo Fraud"
    }
}

pub enum DuplexAction {
    None,
    Query {
        store: Rc<Store>,
        user_range: TimeSpan,
    },
    Start {
        store: Rc<Store>,
        users: Vec<User>,
    },
    Done {
        store: Rc<Store>,
        investigations: usize,
    },
    Reset,
}

// -------------------- Date Select UI --------------------

const TIME_FMT: &str = "%H:%M";

pub struct DateSelectUi {
    store: Rc<Store>,
    user_date: (NaiveDate, NaiveDate),
    user_time: (String, String),
    issue: Option<String>,
    action: Option<DuplexAction>,
}

impl DateSelectUi {
    pub fn new(store: Rc<Store>) -> Self {
        let now = chrono::Local::now();
        let date = now.date_naive();
        let hour_ago = (now - chrono::Duration::hours(1))
            .format(TIME_FMT)
            .to_string();
        let time = now.format(TIME_FMT).to_string();
        Self {
            store,
            user_date: (date, date),
            user_time: (hour_ago, time),
            issue: None,
            action: None,
        }
    }

    fn vibe_check(&mut self) -> bool {
        match self.user_date.0.cmp(&self.user_date.1) {
            std::cmp::Ordering::Less => (),
            std::cmp::Ordering::Equal => {
                if let Ok(user_time_start) =
                    chrono::NaiveTime::parse_from_str(&self.user_time.0, TIME_FMT)
                {
                    if let Ok(user_time_end) =
                        chrono::NaiveTime::parse_from_str(&self.user_time.1, TIME_FMT)
                    {
                        if user_time_start >= user_time_end {
                            self.issue = Some("Start is after end".to_owned());
                            return false;
                        }
                    } else {
                        self.issue = Some("End time is invalid".to_owned());
                        return false;
                    }
                } else {
                    self.issue = Some("Start time is invalid".to_owned());
                    return false;
                }
            }
            std::cmp::Ordering::Greater => {
                self.issue = Some("Start is after end".to_owned());
                return false;
            }
        }

        self.issue = None;
        true
    }

    fn action_login(&mut self) {
        if !self.vibe_check() {
            return;
        }

        self.action = Some(DuplexAction::Query {
            store: Rc::clone(&self.store),
            user_range: crate::queries::splunk::TimeSpan::from(self.user_date, &self.user_time),
        });
    }
}

impl View for DateSelectUi {
    fn ui(&mut self, ui: &mut egui::Ui, _ctx: &egui::Context) -> DuplexAction {
        if !self.store.has_hdtools() {
            ui.label(egui::RichText::new("You did not provide a shibession and won't be\nable to take advantage of advanced filtering").color(super::color::LOVE));
        }

        egui::Grid::new("time_range")
            .min_col_width(50.0)
            .show(ui, |ui| {
                ui.label("Time Range:");
                ui.menu_button("📅", |ui| {
                    ui.vertical_centered(|ui| ui.label("Presets"));
                    if ui.button("Past Hour").clicked() {
                        let now = chrono::Local::now();
                        let hour = now.hour();
                        self.user_date = (now.date_naive(), now.date_naive());
                        self.user_time = (format!("{:02}:00", hour - 1), format!("{:02}:00", hour));
                        ui.close_menu();
                    }
                    if ui.button("Over night").clicked() {
                        let now = chrono::Local::now();
                        self.user_date = (
                            now.date_naive() - chrono::Duration::days(1),
                            now.date_naive(),
                        );
                        self.user_time = ("16:00".to_owned(), now.format(TIME_FMT).to_string());
                        ui.close_menu();
                    }
                    if ui.button("Over weekend").clicked() {
                        let now = chrono::Local::now();
                        self.user_date = (
                            now.date_naive() - chrono::Duration::days(3),
                            now.date_naive(),
                        );
                        self.user_time = ("16:00".to_owned(), now.format(TIME_FMT).to_string());
                        ui.close_menu();
                    }
                });
                ui.end_row();

                ui.add(DatePickerButton::new(&mut self.user_date.0).id_source("UL"));
                ui.add(TextEdit::singleline(&mut self.user_time.0).desired_width(40.0));
                ui.end_row();

                ui.add(DatePickerButton::new(&mut self.user_date.1).id_source("UU"));
                ui.add(TextEdit::singleline(&mut self.user_time.1).desired_width(40.0));
                ui.end_row();
            });

        let enabled = self.vibe_check();
        ui.add_enabled_ui(enabled, |ui| {
            let button = ui.add_sized(egui::vec2(140.0, 25.0), egui::Button::new("Let's ride!"));
            if button.clicked() {
                self.action_login();
            }
        });

        if let Some(issue) = &self.issue {
            ui.label(egui::RichText::new(issue).color(super::color::LOVE));
        }

        self.action.take().unwrap_or(DuplexAction::None)
    }

    fn store(&self) -> &Rc<Store> {
        &self.store
    }
}

// -------------------- Loading UI --------------------

pub struct LoadingUi {
    pub store: Rc<Store>,
    run: Option<JoinHandle<Vec<User>>>,
    action: Option<DuplexAction>,
}

impl LoadingUi {
    pub fn new(store: Rc<Store>, run: JoinHandle<Vec<User>>) -> Self {
        LoadingUi {
            store,
            run: Some(run),
            action: None,
        }
    }
}

impl View for LoadingUi {
    fn ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) -> DuplexAction {
        if self
            .run
            .as_ref()
            .expect("LoadingUi run should be some by now")
            .is_finished()
        {
            let users = self
                .run
                .take()
                .expect("Failed to take users from JoinHandle")
                .join()
                .expect("Couldn't get users from thread");
            self.action = Some(DuplexAction::Start {
                store: Rc::clone(&self.store),
                users,
            });
        } else {
            let s = self.store.progress();
            if s == 0.0 {
                ui.label("Querying splunk...");
            } else {
                ui.label("Vibe checking users...");
            }
            ui.add(
                egui::widgets::ProgressBar::new(s)
                    .animate(true)
                    .desired_width(325.0),
            );
        }

        std::thread::sleep(std::time::Duration::from_millis(10));
        ctx.request_repaint(); // Call repaint to re-check if the thread is finished

        self.action.take().unwrap_or(DuplexAction::None)
    }

    fn store(&self) -> &Rc<Store> {
        &self.store
    }
}

// -------------------- Main UI --------------------

pub struct MainUi {
    days: i64,
    more_logs: Option<(JoinHandle<Option<Vec<Login>>>, usize)>,
    store: Rc<Store>,
    user_idx: usize,
    users: Vec<User>,
    action: Option<DuplexAction>,
}

impl MainUi {
    pub fn new(store: Rc<Store>, users: Vec<User>) -> Self {
        Self {
            users,
            store,
            user_idx: 0,
            more_logs: None,
            days: 30,
            action: None,
        }
    }

    fn cur_user(&self) -> &User {
        &self.users[self.user_idx]
    }

    fn next_user(&mut self) {
        if self.user_idx + 1 >= self.users.len() {
            self.action = Some(DuplexAction::Done {
                store: Rc::clone(&self.store),
                investigations: self.users.len(),
            });
            return;
        }
        self.user_idx += 1;
    }

    fn prev_user(&mut self) {
        self.user_idx = self.user_idx.saturating_sub(1);
    }

    fn progress(&self) -> f32 {
        (self.user_idx + 1) as f32 / self.users.len() as f32
    }

    fn handle_keypresses(&mut self, ctx: &egui::Context) {
        ctx.input(|i| {
            if i.key_pressed(Key::P) || i.key_pressed(Key::K) || i.key_pressed(Key::ArrowLeft) {
                self.prev_user()
            }
            if i.key_pressed(Key::N) || i.key_pressed(Key::J) || i.key_pressed(Key::ArrowRight) {
                self.next_user();
            }
            if i.key_pressed(Key::I) {
                // Toggle investigated
                let user = self.cur_user();

                let investigated = user.investigated;
                self.store
                    .mark_investigated(user.name.to_owned(), !investigated);
                self.users[self.user_idx].investigated = !investigated;
            }
        });
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let user = &self.cur_user();
            ui.heading("User");
            let heading = ui.add(
                Label::new(
                    RichText::new(user.name.to_owned())
                        .heading()
                        .color(color::PINE),
                )
                .sense(egui::Sense::click()),
            );
            if heading.clicked() {
                ui.output_mut(|o| o.copied_text = user.name.to_owned());
            }
            let reason = user
                .reasons
                .iter()
                .map(|r| r.to_string())
                .collect::<Vec<String>>()
                .join(", ");
            ui.heading(format!("flagged for {} - score {}", reason, user.score));

            ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                ui.menu_button("More logs", |ui| {
                    ui.add(egui::Slider::new(&mut self.days, 7..=90).text("days"));
                    if ui.button("Get").clicked() {
                        ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Progress);
                        let user = self.cur_user().name.to_owned();
                        self.more_logs =
                            Some((self.store.more_info(user, self.days), self.user_idx));
                        ui.close_menu();
                    }
                });

                if ui
                    .button("I'm done")
                    .on_hover_text("Go to final screen")
                    .clicked()
                {
                    self.action = Some(DuplexAction::Done {
                        store: Rc::clone(&self.store),
                        investigations: self.user_idx + 1,
                    });
                }

                let user = &self.cur_user();
                if !user.investigated {
                    let button = ui
                        .button("(I)gnore")
                        .on_hover_text("User will not reapprear for 24 hours");
                    if button.clicked() {
                        self.store.mark_investigated(user.name.to_owned(), true);
                        self.users[self.user_idx].investigated = true;
                    }
                } else if ui.button("Un(I)gnore").clicked() {
                    self.store.mark_investigated(user.name.to_owned(), false);
                    self.users[self.user_idx].investigated = false;
                }

                if ui.button("(N)ext").clicked() {
                    self.next_user();
                }
                if ui.button("(P)revious").clicked() {
                    self.prev_user();
                }
            });
        });
    }

    fn hdtools_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let user = &self.cur_user();
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

        let table = TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .columns(Column::auto(), 6)
            .column(Column::remainder());
        let user = &self.cur_user();
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
                            "Left click to copy to clipboard\nRight click to view service details\nMouse over for ASN",
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
                            egui::Label::new(
                                RichText::new(format!("{}", login.time.format("%T %D"))).color(
                                    if login.flag_reasons.is_empty() {
                                        color::TEXT
                                    } else {
                                        color::LOVE
                                    },
                                ),
                            )
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

    fn progress_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(format!(
                "[{}/{} users]",
                self.user_idx + 1,
                self.users.len()
            ));
            ui.add(ProgressBar::new(self.progress()).show_percentage());
        });
    }
}

impl View for MainUi {
    fn ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) -> DuplexAction {
        if self.users.is_empty() {
            ui.heading("No users to check");
            if ui.button("Rerun").clicked() {
                self.action = Some(DuplexAction::Reset);
            }

            return DuplexAction::None;
        }

        if let Some(more_logs) = &self.more_logs {
            if more_logs.0.is_finished() {
                if let Some((rx, i)) = self.more_logs.take() {
                    if let Some(logins) = rx.join().expect("Couldn't get more logs from thread") {
                        for login in logins {
                            if !self.users[i].logins.contains(&login) {
                                self.users[i].logins.push(login);
                            }
                        }
                        self.users[i].logins.sort();
                    }
                }
                self.more_logs = None;
            } else {
                ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Progress);
                std::thread::sleep(std::time::Duration::from_millis(10));
                ctx.request_repaint(); // Call repaint to re-check if the thread is finished
            }
        }

        StripBuilder::new(ui)
            .sizes(Size::exact(20.0), 3)
            .size(Size::remainder().at_least(100.0))
            .vertical(|mut strip| {
                strip.cell(|ui| self.progress_bar(ui));
                strip.cell(|ui| self.top_bar(ui));
                strip.cell(|ui| self.hdtools_bar(ui));
                strip.cell(|ui| self.table(ui));
            });
        if ui.ui_contains_pointer() && !ctx.wants_keyboard_input() {
            self.handle_keypresses(ctx);
        }

        self.action.take().unwrap_or(DuplexAction::None)
    }

    fn store(&self) -> &Rc<Store> {
        &self.store
    }
}

// -------------------- Completed Ui --------------------

pub struct DoneUi {
    pub store: Rc<Store>,
    action: Option<DuplexAction>,
    investigations: usize,
    tx: Option<JoinHandle<Option<()>>>,
    failed: bool,
}

impl DoneUi {
    pub fn new(store: Rc<Store>, investigations: usize) -> Self {
        Self {
            store,
            action: None,
            investigations,
            tx: None,
            failed: false,
        }
    }
}

impl View for DoneUi {
    fn ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) -> DuplexAction {
        if let Some(tx) = &self.tx {
            if tx.is_finished() {
                let resp = self
                    .tx
                    .take()
                    .expect("Failed to take DoneUi tx")
                    .join()
                    .expect("Couldn't join post_osiris thread");
                match resp {
                    None => self.failed = true,
                    Some(()) => {
                        self.tx = None;
                        self.failed = false
                    }
                }
            } else {
                ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Progress);
                std::thread::sleep(std::time::Duration::from_millis(10));
                ctx.request_repaint(); // Call repaint to re-check if the thread is finished
            }
        }
        ui.vertical(|ui| {
            ui.heading("🎉 Yeehaw! You're done 🎉");
            ui.horizontal(|ui| {
                ui.label("Investigations");
                let investigations = ui.add(
                    egui::Label::new(self.investigations.to_string()).sense(egui::Sense::click()),
                );
                if investigations.clicked() {
                    ui.output_mut(|o| o.copied_text = self.investigations.to_string());
                }
            });
            ui.horizontal(|ui| {
                if ui.button("Send to Osiris").clicked() {
                    let data = osiris::Data {
                        investigations: vec![("Duo".to_owned(), self.investigations as i64)],
                        incidents: vec![],
                    };

                    self.tx = Some(
                        self.store
                            .post_osiris(chrono::Local::now().date_naive(), data),
                    );
                }
                if ui.button("Rerun duplex").clicked() {
                    self.action = Some(DuplexAction::Reset);
                }
            });
        });

        self.action.take().unwrap_or(DuplexAction::None)
    }

    fn store(&self) -> &Rc<Store> {
        &self.store
    }
}
