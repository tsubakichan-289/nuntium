use chrono::Local;

pub fn debug_print(message: &str) {
	let dayte = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");

	if cfg!(debug_assertions) {
		println!("[{}] DEBUG: {}", dayte, message);
	}
}