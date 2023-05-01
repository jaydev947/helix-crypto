#[derive(Debug)]
pub(super) struct HelixError {
    code: String,
    detailed_code: String,
    message: String,
}

impl HelixError {
    pub(super) fn from(code: &str, detailed_code: &str, message: &str) -> HelixError {
        HelixError {
            code: String::from(code),
            detailed_code: String::from(detailed_code),
            message: String::from(message),
        }
    }
}
