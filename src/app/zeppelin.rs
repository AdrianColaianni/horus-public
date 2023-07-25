//! Metric tracking with Osiris
//!
//! This is the front end for Osiris, the backend metric tracker running on the old wiki server (RIP
//! In Peace).  This stores no information on default categories and everything is pulled from the
//! server.
use super::color;
use crate::queries::osiris;
use crate::store::Store;
use chrono::NaiveDate;
use egui::RichText;
use egui_extras::Column;
use std::rc::Rc;
use std::thread::JoinHandle;

pub struct Zeppelin {
    store: Rc<Store>,
    /// Rx might contain a JoinHandle which might return a struct which contains a vector which
    /// contains a tupple which contains a string and a u64 and vector which contains a tupple
    /// which contains a string and a u64
    rx: Option<JoinHandle<Option<osiris::Data>>>,
    /// Used to determine if POST was successful
    tx: Option<JoinHandle<Option<()>>>,
    /// Selected date to pull
    date: NaiveDate,
    /// List of incidents and count from server
    incidents: Vec<(String, i64)>,
    /// List of count to add to total
    incident_add: Vec<i64>,
    /// Stores the new incident name
    new_incident: String,
    /// List of investigations and count from the server
    investigations: Vec<(String, i64)>,
    /// List of count to add to total
    investigation_add: Vec<i64>,
    /// Stores new investigation name
    new_investigation: String,
    /// True if Zeppelin failed to pull data from Osiris, false otherwise
    failed: bool,
    /// True if Zeppelin fails to send data to Osiris
    post_failed: bool,
    /// Time range for report
    report: (NaiveDate, NaiveDate),
    /// Keeps track of pulling report data
    report_rx: Option<JoinHandle<()>>,
    /// Output file name
    file: String,
}

impl Zeppelin {
    pub fn new(store: Rc<Store>) -> Self {
        let date = chrono::Local::now().date_naive();
        let rx = Some(store.run_zeppelin(date));
        Self {
            store,
            rx,
            tx: None,
            date,
            incidents: vec![],
            incident_add: vec![],
            new_incident: String::new(),
            investigations: vec![],
            investigation_add: vec![],
            new_investigation: String::new(),
            failed: false,
            post_failed: false,
            report: (date, date),
            report_rx: None,
            file: String::new(),
        }
    }
}

impl super::panels::Panel for Zeppelin {
    fn name(&self) -> &'static str {
        "☫ Zeppelin"
    }

    fn desc(&self) -> &'static str {
        "Metric Tracking with Osiris"
    }

    fn show(&mut self, ctx: &egui::Context, open: &mut bool) {
        egui::Window::new(RichText::new(self.name()).color(color::GOLD))
            .open(open)
            .fixed_size(egui::vec2(200.0, 800.0))
            .vscroll(false)
            .show(ctx, |ui| {
                if let Some(rx) = &self.rx {
                    if rx.is_finished() {
                        match self
                            .rx
                            .take()
                            .expect("Failed to take rx from Zeppelin")
                            .join()
                            .expect("Failed to get Osiris info from thread")
                        {
                            Some(data) => {
                                self.failed = false;
                                self.investigation_add = vec![0; data.investigations.len()];
                                self.investigations = data.investigations;
                                self.incident_add = vec![0; data.incidents.len()];
                                self.incidents = data.incidents;
                            }
                            None => self.failed = true,
                        }
                    } else {
                        ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Wait);
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        ctx.request_repaint(); // Call repaint to re-check if the thread is finished
                    }
                }

                if let Some(tx) = &self.tx {
                    if tx.is_finished() {
                        match self
                            .tx
                            .take()
                            .expect("Failed to take tx from Zeppelin")
                            .join()
                            .expect("Failed to fet Osiris post status from thread")
                        {
                            Some(_) => {
                                self.post_failed = false;
                                self.rx = Some(self.store.run_zeppelin(self.date));
                            }
                            None => self.post_failed = true,
                        }
                    } else {
                        ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Wait);
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        ctx.request_repaint(); // Call repaint to re-check if the thread is finished
                    }
                }

                if let Some(rx) = &self.report_rx {
                    if rx.is_finished() {
                        self.report_rx = None;
                    } else {
                        ui.output_mut(|o| o.cursor_icon = egui::CursorIcon::Wait);
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        ctx.request_repaint(); // Call repaint to re-check if the thread is finished
                    }
                }

                if self.post_failed {
                    ui.label(RichText::new("Couldn't post data to Osiris").color(color::LOVE));
                }
                if self.failed {
                    ui.label(RichText::new("Couldn't fetch data from Osiris").color(color::LOVE));
                }

                self.ui(ui);
            });
    }
}

impl Zeppelin {
    fn ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.add(
                egui_extras::DatePickerButton::new(&mut self.date)
                    .arrows(false)
                    .calendar_week(false),
            );
            ui.add_enabled_ui(self.rx.is_none(), |ui| {
                if ui.button("Refresh").clicked() {
                    self.rx = Some(self.store.run_zeppelin(self.date));
                }
            });
            ui.menu_button("Save report", |ui| {
                ui.add(egui_extras::DatePickerButton::new(&mut self.report.0));
                ui.add(egui_extras::DatePickerButton::new(&mut self.report.1));
                ui.horizontal(|ui| {
                    ui.label("File");
                    ui.text_edit_singleline(&mut self.file);
                });
                if ui.button("Save").clicked() {
                    self.report_rx =
                        Some(self.store.save_report(self.file.to_owned(), self.report));
                }
            });
        });

        if self.failed {
            return;
        }

        ui.vertical_centered(|ui| {
            ui.label(RichText::new("Investigations").heading().color(color::PINE))
        });
        ui.push_id("investigation_table", |ui| {
            ui.set_max_height(300.0);
            egui_extras::TableBuilder::new(ui)
                .striped(true)
                .resizable(false)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::remainder())
                .columns(Column::exact(40.0), 2)
                .header(20.0, |mut header| {
                    for title in ["Name", "Value", "Add"] {
                        header.col(|ui| {
                            ui.label(title);
                        });
                    }
                })
                .body(|body| {
                    body.rows(20.0, self.investigations.len(), |i, mut row| {
                        let inv = &self.investigations[i];
                        row.col(|ui| {
                            ui.label(&inv.0);
                        });
                        row.col(|ui| {
                            ui.label(format!("{}", inv.1));
                        });
                        row.col(|ui| {
                            ui.add(egui::DragValue::new(&mut self.investigation_add[i]).speed(0.3));
                        });
                    });
                });
        });

        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.new_investigation).desired_width(100.0));
            if ui.button("Add category").clicked() {
                self.investigations
                    .push((self.new_investigation.to_owned(), 0));
                self.investigation_add.push(0);
                self.new_investigation.clear();
            }
        });

        ui.separator();
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("Incidents").heading().color(color::PINE))
        });
        ui.push_id("incident_table", |ui| {
            ui.set_max_height(300.0);
            egui_extras::TableBuilder::new(ui)
                .striped(true)
                .resizable(false)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::remainder())
                .columns(Column::exact(40.0), 2)
                .header(20.0, |mut header| {
                    for title in ["Name", "Value", "Add"] {
                        header.col(|ui| {
                            ui.label(title);
                        });
                    }
                })
                .body(|body| {
                    body.rows(20.0, self.incidents.len(), |i, mut row| {
                        let inc = &self.incidents[i];
                        row.col(|ui| {
                            ui.label(&inc.0);
                        });
                        row.col(|ui| {
                            ui.label(format!("{}", inc.1));
                        });
                        row.col(|ui| {
                            ui.add(egui::DragValue::new(&mut self.incident_add[i]).speed(0.3));
                        });
                    });
                });
        });

        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.new_incident).desired_width(100.0));
            if ui.button("Add category").clicked() {
                self.incidents.push((self.new_incident.to_owned(), 0));
                self.incident_add.push(0);
                self.new_incident.clear();
            }
        });

        ui.vertical_centered(|ui| {
            ui.add_enabled_ui(self.tx.is_none(), |ui| {
                if ui.button("Make it so!").clicked() {
                    let incidents: Vec<_> = self
                        .incident_add
                        .iter()
                        .enumerate()
                        .filter_map(|(i, inc)| {
                            if *inc != 0 {
                                Some((self.incidents[i].0.to_owned(), *inc))
                            } else {
                                None
                            }
                        })
                        .collect();

                    let investigations: Vec<_> = self
                        .investigation_add
                        .iter()
                        .enumerate()
                        .filter_map(|(i, inv)| {
                            if *inv != 0 {
                                Some((self.investigations[i].0.to_owned(), *inv))
                            } else {
                                None
                            }
                        })
                        .collect();

                    self.tx = Some(self.store.post_osiris(
                        self.date,
                        osiris::Data {
                            incidents,
                            investigations,
                        },
                    ));
                }
            });
        });
    }
}
