//! Login page for HORUS
//!
//! HORUS will check credentials upon login and will refuse if they are invalid.  The analyst_name
//! is used for Cherwell ticket templates and cannot be changed after logging in.
use crate::{app::color, storage::Storage};
use egui::{RichText, TextEdit};

pub struct LoginUI {
    storage: Option<Storage>,
    username: String,
    password: String,
    shibsession: [String; 2],
    analyst_name: String,
    issue: Option<String>,
    action: Option<super::StateUIAction>,
}

impl super::StateUIVariant for LoginUI {
    fn update_panel(&mut self, ctx: &egui::Context) -> super::StateUIAction {
        egui::CentralPanel::default().show(ctx, |ui| self.ui(ui));
        self.handle_keypresses(ctx);
        self.action.take().unwrap_or(super::StateUIAction::None)
    }
}

impl LoginUI {
    fn ui(&mut self, ui: &mut egui::Ui) -> egui::Response {
        let available = ui.available_size();

        ui.centered_and_justified(|ui| {
            ui.add(
                egui::Label::new(
                    RichText::new(
                        r#"                                   _
                                 ,d8b,
                         _,,aadd8888888bbaa,,_
                    _,ad88P"""8,  I8I  ,8"""Y88ba,_
                 ,ad88P" `Ya  `8, `8' ,8'  aP' "Y88ba,
               ,d8"' "Yb   "b, `b  8  d' ,d"   dP" `"8b,
              dP"Yb,  `Yb,  `8, 8  8  8 ,8'  ,dP'  ,dP"Yb
           ,ad8b, `Yb,  "Ya  `b Y, 8 ,P d'  aP"  ,dP' ,d8ba,
          dP" `Y8b, `Yb, `Yb, Y,`8 8 8',P ,dP' ,dP' ,d8P' "Yb
         ,8:::::::Yb, `Yb,`Yb,`8 8 8 8 8',dP',dP' ,dY:::::::8,
         dP     `Yb`Yb, Yb,`8b 8 8 8 8 8 d8',dP ,dP'dP'     Yb
        ,8:::::::::b "8, Yba888888888888888adP ,8" d:::::::::8,
        dP        `Yb,`Y8P""'             `""Y8P',dP'        Yb
       ,8::::::::::P"Y8P'_.---.._     _..---._`Y8P"Y::::::::::8,
       dP         d'  8 '  ____  `. .'  ____  ` 8  `b         Yb
      ,8::::::::::8   8   <(@@)>  | |  <(@@)>   8   8::::::::::8,
      dP          8   8    `"""         """'    8   8          Yb
     ,8:::::::::::8,  8          ,   ,  |".,    8  ,8:::::::::::8,
     dP           `b  8,        (.-_-.)        ,8  d'           Yb
    ,8:::::::::::::Yaa8b      ,'       `,      d8aaP:::::::::::::8,
    dP               ""8b     _,gd888bg,_     d8""               Yb
   ,8:::::::::::::::::::8b,    ""Y888P""    ,d8:::::::::::::::::::8,
   dP                   "8"b,             ,d"8"                   Yb
  ,8::::::::::::::::::::::8,"Ya,_,ggg,_,aP",8::::::::::::::::::::::8,
  dP                      "8,  "8"\x/"8"  ,8"                      Yb
 ,8:::::::::::::::::::::::::b   8\\x//8   d:::::::::::::::::::::::::8,
 8888bgg,_                  8   8\\x//8   8                  _,ggd8888
  `"Yb, ""8:::::::::::::::::8   Y\\x//P   8:::::::::::::::::8"" ,dP"'
    _d8bg,_"8,              8   `b\x/d'   8              ,8"_,gd8b_
  ,iP"   "Yb,8::::::::::::::8    8\x/8    8::::::::::::::8,dP"  `"Yi,
 ,P"    __,888              8    8\x/8    8              888,__    "Y,
,8baaad8P"":Y8::::::::::::::8 aaa8\x/8aaa 8::::::::::::::8P:""Y8baaad8,
dP"'<>-<>-<>-8              8 8::8\x/8::8 8              8-<>-<>-<>`"Yb
8-<>-<>-<>-<>8::::::::::::::8 8::88888::8 8::::::::::::::8<>-<>-<>-<>-8
8>-<>-<>-<>-<8,             8 8:::::::::8 8             ,8>-<>-<>-<>-<8
8<>-<>-<>-<>-8::::::::::::::8 8:::::::::8 8::::::::::::::8-<>-<>-<>-<>8
8-<>-<>-<>-<>Ya             8 8:::::::::8 8             aP<>-<>-<>-<>-8
8>-<>-<>-<>-<>8:::::::::::::8 8:::::::::8 8:::::::::::::8<>-<>-<>-<>-<8
8<>-<>-<>-<>-<Ya            8 8:::::::::8 8            aP>-<>-<>-<>-<>8
Ya<>-<>-<>-<>-<8::::::::::::8 8:::::::::8 8::::::::::::8>-<>-<>-<>-<>aP
`8;<>-<>-<>-<>-<Ya,         8 8:::::::::8 8         ,aP>-<>-<>-<>-<>;8'
 Ya-<>-<>-<>-<>-<>"Y888888888 8:::::::::8 888888888P"<>-<>-<>-<>-<>-aP
 `8;-<>-<>-<>-<>-<>-<>-<""""Y8888888888888P"""">-<>-<>-<>-<>-<>-<>-;8'
  Ya>-<>-<>-<>-<>-<>-<>-<>-<>-<>-<>|<>-<>-<>-<>-<>-<>-<>-<>-<>-<>-<aP
   "b;-<>-<>-<>-<>-<>-<>-<>-<>-<>-<|>-<>-<>-<>-<>-<>-<>-<>-<>-<>-;d"
    `Ya;<>-<>-<>-<>-<>-<>-<>-<>-<>-|-<>-<>-<>-<>-<>-<>-<>-<>-<>;aP'
      `Ya;>-<>-<>-<>-<>-<>-<>-<>-<>|<>-<>-<>-<>-<>-<>-<>-<>-<;aP'
         "Ya;<>-<>-<>-<>-<>-<>-<>-<|>-<>-<>-<>-<>-<>-<>-<>;aP"
            "Yba;;;-<>-<>-<>-<>-<>-|-<>-<>-<>-<>-<>-;;;adP"
                `"""""""Y888888888888888888888P"""""""'"#,
                    )
                    .size(20.0)
                    .color(color::MUTED)
                    .monospace(),
                )
                .wrap(false),
            )
        });
        // Shamelessly stolen from https://github.com/terhechte/postsack
        let desired_size = egui::vec2(240.0, 230.0);
        let paint_rect = egui::Rect::from_min_size(
            egui::Pos2 {
                x: available.x / 2.0 - desired_size.x / 2.0,
                y: available.y / 2.0 - desired_size.y / 2.0,
            },
            desired_size,
        );
        let center = paint_rect.shrink(15.0);
        super::shadow_background(
            ui.painter(),
            paint_rect,
            ui.visuals().window_fill,
            egui::Stroke::new(1.0, color::HIGHLIGHT_HIGH),
            12.0,
            egui::epaint::Shadow::big_dark(),
        );

        let response = ui.allocate_ui_at_rect(center, |ui| {
            ui.vertical_centered(|ui| ui.heading(RichText::new("👁HORUS").color(color::GOLD)));

            ui.style_mut()
                .visuals
                .widgets
                .noninteractive
                .bg_stroke
                .color = color::IRIS;
            ui.separator();

            ui.label("Splunk credentials");
            ui.horizontal(|ui| {
                ui.add(
                    TextEdit::singleline(&mut self.username)
                        .desired_width(100.0)
                        .hint_text("username"),
                );
                ui.add(
                    TextEdit::singleline(&mut self.password)
                        .desired_width(100.0)
                        .hint_text("password")
                        .password(true),
                );
            });

            ui.add_space(7.0);

            ui.label("HDTools shibsession cookie (optional)");
            ui.horizontal(|ui| {
                ui.add(
                    TextEdit::singleline(&mut self.shibsession[0])
                        .desired_width(100.0)
                        .hint_text("shibsession name"),
                );
                ui.add(
                    TextEdit::singleline(&mut self.shibsession[1])
                        .desired_width(100.0)
                        .hint_text("shibsession value"),
                );
            });

            ui.add_space(5.0);

            ui.label("Your name");
            ui.add(
                TextEdit::singleline(&mut self.analyst_name)
                    .desired_width(100.0)
                    .hint_text("Your Name"),
            );

            ui.add_space(5.0);

            let button_size: egui::Vec2 = (center.width(), 25.0).into();
            let enabled = !self.username.is_empty() && !self.password.is_empty();
            ui.add_enabled_ui(enabled, |ui| {
                let button = ui.add_sized(button_size, egui::Button::new("Login"));
                if button.clicked() {
                    self.action_login();
                }
            });

            if let Some(issue) = &self.issue {
                ui.vertical_centered(|ui| ui.label(RichText::new(issue).color(color::LOVE)));
            }
        });

        response.response
    }

    fn action_login(&mut self) {
        if self.username.is_empty() {
            self.issue = Some("Username is empty".to_owned());
            return;
        } else if self.password.is_empty() {
            self.issue = Some("Password is empty".to_owned());
            return;
        }

        let hdtools = if !self.shibsession.iter().any(|s| s.is_empty()) {
            let shib = self.shibsession.join("=");
            Some(std::thread::spawn(move || {
                crate::queries::hdtools::HDTools::new(shib)
            }))
        } else {
            None
        };

        let storage = self.storage.as_mut().expect("Failed to get storage");
        storage.set_username(self.username.to_owned());
        storage.set_analyst_name(self.analyst_name.to_owned());

        let splunk = match crate::queries::splunk::Splunk::new(&self.username, Some(&self.password))
        {
            Some(s) => s,
            None => {
                self.issue = Some("Invalid Splunk creds".to_owned());
                return;
            }
        };

        let hdtools = match hdtools {
            Some(j) => match j.join().expect("Failed to join with hdtools thread") {
                Some(hdtools) => Some(hdtools),
                None => {
                    self.issue = Some("Invalid shibsession".to_owned());
                    return;
                }
            },
            None => None,
        };

        let store = crate::store::Store::new(
            splunk,
            hdtools,
            self.storage
                .take()
                .expect("Failed to pass storage to store"),
            self.analyst_name.to_owned(),
        );

        self.action = Some(super::StateUIAction::Login { store });
    }

    fn handle_keypresses(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.key_pressed(egui::Key::Enter)) {
            self.action_login();
        }
    }
}

impl Default for LoginUI {
    fn default() -> Self {
        let storage = Storage::load();
        LoginUI {
            username: storage.get_username(),
            password: "".to_owned(),
            shibsession: ["".to_owned(), "".to_owned()],
            analyst_name: storage.get_analyst_name(),
            storage: Some(storage),
            issue: None,
            action: None,
        }
    }
}
