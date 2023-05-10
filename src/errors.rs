#[derive(Debug)]
pub struct HelixError {
    pub code: String,
    pub detailed_code: String,
    pub message: String,
}

impl HelixError {
    pub fn from(code: &str, detailed_code: &str, message: &str) -> HelixError {
        HelixError {
            code: String::from(code),
            detailed_code: String::from(detailed_code),
            message: String::from(message),
        }
    }
}
