//! Main ui for HORUS
use super::{color, panels::Panels};
use crate::store::Store;
use chrono::Datelike;
use std::rc::Rc;

pub struct MainUI {
    /// Apps are held in this struct
    panels: Panels,
    /// Image of Horus in the background
    horus: Option<egui::TextureHandle>,
    /// :)
    smells_like: usize,
    color_my_pencils: bool,
}

impl super::StateUIVariant for MainUI {
    fn update_panel(&mut self, ctx: &egui::Context) -> super::StateUIAction {
        egui::SidePanel::right("right_panel")
            .resizable(false)
            .default_width(150.0)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.label(egui::RichText::new("👁HORUS").heading().color(color::GOLD))
                });
                ui.scope(|ui| {
                    ui.style_mut()
                        .visuals
                        .widgets
                        .noninteractive
                        .bg_stroke
                        .color = color::IRIS;
                    ui.separator();
                });
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.with_layout(egui::Layout::top_down_justified(egui::Align::LEFT), |ui| {
                        self.panels.checkboxes(ui);
                    });
                });
            });

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(egui::Color32::BLACK))
            .show(ctx, |ui| {
                let y = ui.available_size().y;

                if self.color_my_pencils {
                    let funky = chrono::Local::now();
                    let monkey = funky.day() % 10 == 0;
                    if self.smells_like < 42
                        && monkey
                        && !std::path::Path::new("/tmp/shiver_me_timbers").exists()
                    {
                        if std::fs::File::create("/tmp/shiver_me_timbers").is_err() {
                            return;
                        }
                        self.color_my_pencils = false;
                        log::warn!(":)");
                        // let image = image::io::Reader::open("mong.webp").unwrap().decode().unwrap();
                        // let size = [image.width() as _, image.height() as _];
                        // println!("{:?}", size);
                        // let image_buffer = image.to_rgba8();
                        // let pixels = image_buffer.as_flat_samples();
                        // let image = egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice());
                        // std::fs::write("mong.ci", image.as_raw()).unwrap();
                        let image = egui::ColorImage::from_rgba_unmultiplied(
                            [360, 640],
                            std::include_bytes!("../../sphinx.ci").as_slice(),
                        );
                        let image = ui.ctx().load_texture("mong", image, Default::default());
                        let size = image.size_vec2();
                        let size = egui::vec2(y * size.x / size.y, y);
                        ui.add(egui::Image::new(&image, size));
                        ctx.request_repaint_after(std::time::Duration::from_millis(5));
                        return;
                    }
                }
                let horus: &egui::TextureHandle = self.horus.get_or_insert_with(|| {
                    let image = egui::ColorImage::from_rgba_unmultiplied(
                        [540, 960],
                        std::include_bytes!("../../horus.ci").as_slice(),
                    );
                    ui.ctx().load_texture("horus", image, Default::default())
                });
                let size = horus.size_vec2();
                let size = egui::vec2(y * size.x / size.y, y);
                ui.add(egui::Image::new(horus, size));
            });

        self.panels.windows(ctx);

        super::StateUIAction::None
    }
}

impl MainUI {
    pub fn new(store: Store) -> Self {
        let store = Rc::new(store);
        let in_here = store.analyst_name();
        Self {
            smells_like: up_dog(in_here),
            panels: Panels::new(store),
            horus: None,
            color_my_pencils: true,
        }
    }
}

fn up_dog(what_is: &str) -> usize {
    what_is.chars().map(|w| w as usize % 15).sum::<usize>()
}
