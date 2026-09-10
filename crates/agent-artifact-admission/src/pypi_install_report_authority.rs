use crate::InstallIntent;

/// Return whether a direct pip install asks the installer to write its JSON report
/// to a caller-selected destination outside the reviewed artifact mutation contract.
pub(crate) fn requests_unapproved_pypi_report_authority(intent: &InstallIntent) -> bool {
    let Some(executable) = intent.argv.first().map(String::as_str) else {
        return false;
    };
    if !matches!(executable, "pip" | "pip3") {
        return false;
    }

    let arguments = &intent.argv[1..];
    if !arguments
        .first()
        .is_some_and(|argument| argument == "install")
    {
        return false;
    }

    arguments
        .iter()
        .skip(1)
        .any(|argument| argument == "--report" || argument.starts_with("--report="))
}
