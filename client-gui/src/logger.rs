use log::LevelFilter;
use fern::Dispatch;
use chrono::Local;
use std::fs;

pub fn setup_logger() -> Result<(), fern::InitError> {
    // Создаем папку для логов если её нет
    let _ = fs::create_dir_all("logs");

    Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{} [{}] {}: {}",
                Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.target(),
                message
            ))
        })
        .level_for("wgpu", log::LevelFilter::Error)
        .level_for("winit", log::LevelFilter::Error)
        .level_for("iced_winit", log::LevelFilter::Error)
        .level_for("iced_wgpu", log::LevelFilter::Error)
        .level_for("wgpu_hal", log::LevelFilter::Error)
        .level_for("wgpu_core", log::LevelFilter::Error)
        .level_for("naga", log::LevelFilter::Error)
        .level_for("cosmic_text", log::LevelFilter::Error)
        .level_for("fontdb", log::LevelFilter::Error)
        .level_for("client-gui", log::LevelFilter::Debug)
        .level(LevelFilter::Debug) // Уровень логирования по умолчанию
        .chain(fern::log_file("logs/app.log")?) // Логи в файл
        .chain(std::io::stdout()) // Логи в консоль
        .apply()?;
    
    Ok(())
}