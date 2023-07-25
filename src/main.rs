mod app;
mod queries;
mod storage;
mod store;
mod user;
use chrono::Timelike;

const PHRASES: [&str; 11] = [
    "I Swear It's Not Skynet!",
    "The EYE",
    "Eyes Eyes Eyes",
    "Beep Boop Kill All Humans",
    "Your Job Will Be Mine",
    "Hehe Haha Monkey",
    "Special Weapons Platform",
    "Duplexing Since Jan 1, 1970",
    "Reccomended By 9/10 Dentists",
    "Not For Human Consumption",
    "Rated E for Epic Gamer",
];

fn main() -> Result<(), eframe::Error> {
    env_logger::init();

    // You need brail fonts to see this
    log::info!("  ⣀⣤⣶⠾⠿⠿⠿⠿⢶⣦⣤⣀⡀");
    log::info!("⣤⠾⠛⠉        ⠉⠙⠛⠻⠷⣶⣤⣤⣤⣀⣀⣀⣀⣀");
    log::info!("    ⢀⣀⣀⣀⣀⣀⡀        ⠉⠉⠉⠉⠉⠉⠉");
    log::info!("  ⣠⡾⢛⣽⣿⣿⣏⠙⠛⠻⠷⣦⣤⣀⡀        ⡀");
    log::info!("⢠⣾⣋⡀⢸⣿⣿⣿⣿  ⢀⣀⣤⣽⡿⠿⠛⠿⠿⠷⠾⠿⠿⠛⠋");
    log::info!("⠻⠛⠛⠻⣶⣽⣿⣿⣿⡶⠿⠛⠋⠉");
    log::info!("    ⣠⣿⡏⠻⣷⣄          ⢠⣶⠶⢶⣤");
    log::info!("    ⢹⣯⠁ ⠈⠛⢷⣤⡀       ⠸⠧  ⢹⡇");
    log::info!("    ⠈⣿     ⠉⠻⠷⣦⣤⣤⣀⣀⣀⣀⣠⣤⡶⠟");
    log::info!("     ⠛         ⠈⠉⠉⠉⠉⠉⠉⠁");

    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(960.0, 540.0)),
        maximized: true,
        ..Default::default()
    };
    let phrase = PHRASES[chrono::Utc::now().second() as usize % PHRASES.len()];
    eframe::run_native(
        &format!("HORUS: {}", phrase),
        options,
        Box::new(|_cc| Box::<app::StateUI>::default()),
    )?;
    Ok(())
}
