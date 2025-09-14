#![windows_subsystem = "windows"]

use iced::Size;

use crate::gui::app::App;
use log::{error, info};

mod gui;
mod vpn_externs;
mod logger;

fn main() -> Result<(), String> {

     if let Err(e) = logger::setup_logger() {
        eprintln!("Failed to initialize logger: {}", e);
        return Err(e.to_string());
    }

    info!("Starting application");
    
    let icon_bytes = include_bytes!("..\\icon.ico");
    let icon = match iced::window::icon::from_file_data(icon_bytes,None) {
        Ok(icon) => Some(icon),
        Err(e) => {
            error!("Failed to load icon: {e}");
            None
        }
    };
    


    let _ = iced::application("Vinnie Poh", App::update, App::view)
    .window(
        iced::window::Settings {
            size: Size::new(600f32, 360f32),
            min_size: Some(Size::new(600f32, 360f32)),
            max_size: Some(Size::new(1200f32, 720f32)),
            exit_on_close_request: false,
            icon: icon,
            ..Default::default()
        }
    )
    .subscription(|_app| {
        iced::window::events().map(|(id, e)| {
          crate::gui::message::Message::WindowEvent(id, e)
        })
    
    })
    .run();
            
    Ok(())
}
