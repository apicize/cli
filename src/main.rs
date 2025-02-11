use apicize_lib::apicize::{ApicizeExecution, ApicizeExecutionItem};
use apicize_lib::test_runner::cleanup_v8;
use apicize_lib::{open_data_stream, test_runner, ApicizeError, Parameters, Warnings, Workspace};
use clap::Parser;
use colored::Colorize;
use dirs::{config_dir, document_dir};
use log::{Metadata, Record};
use num_format::{SystemLocale, ToFormattedString};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{stderr, stdin, stdout, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::Instant;
use std::{fs, process};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, allow_hyphen_values = true)]
struct Args {
    /// Name of the file to process (or - to read STDIN)
    file: String,
    /// Number of times to run workbook (runs are sequential)
    #[arg(short, long, default_value_t = 1)]
    runs: usize,
    /// Name of the output file name for test results (or - to write to STDOUT)
    #[arg(short, long)]
    output: Option<String>,
    /// Name of the output file name for tracing
    #[arg(short, long)]
    tracing: Option<String>,
    /// Global parameter file name (overriding default location, if available)
    #[arg(short, long)]
    globals: Option<String>,
    /// Print configuration information
    #[arg(short, long, default_value_t = false)]
    info: bool,
}

fn duration_to_ms(d: u128, locale: &SystemLocale) -> String {
    let mut ms = d;
    let mins: u128 = ms / 60000;
    ms -= mins * 60000;
    let secs: u128 = ms / 1000;
    ms -= secs * 1000;
    format!("{:02}:{:02}{}{:03}", mins, secs, locale.decimal(), ms)
}

fn render_execution_item(
    item: &ApicizeExecutionItem,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    let prefix = format!("{:width$}", "", width = level * 3);
    match item {
        ApicizeExecutionItem::Group(group) => {
            let title = format!(
                "{}{} ({} - {} ms)",
                &prefix,
                &group.name,
                duration_to_ms(group.executed_at, locale),
                &group.duration.to_formatted_string(locale),
            );
            writeln!(feedback, "{}", title.white()).unwrap();

            let number_of_runs = group.runs.len();
            for run in &group.runs {
                let mut run_level = level;
                if number_of_runs > 1 {
                    let run_prefix = format!("{:width$}", "", width = (run_level + 1) * 3);
                    run_level += 1;
                    writeln!(
                        feedback,
                        "{}{}",
                        run_prefix,
                        format!("Run {} of {}", run.run_number, number_of_runs).white()
                    )
                    .unwrap();
                }
                for child in &run.items {
                    render_execution_item(child, run_level + 1, locale, feedback);
                }
            }
        }
        ApicizeExecutionItem::Request(request) => {
            let title = format!(
                "{}{} ({} - {} ms)",
                prefix,
                &request.name,
                duration_to_ms(request.executed_at, locale),
                &request.duration.to_formatted_string(locale),
            );
            writeln!(feedback, "{}", title.white()).unwrap();

            let number_of_runs = request.runs.len();
            for run in &request.runs {
                let mut run_level = level;
                if number_of_runs > 1 {
                    let run_prefix = format!("{:width$}", "", width = (run_level + 1) * 3);
                    run_level += 1;
                    writeln!(
                        feedback,
                        "{}{}",
                        run_prefix,
                        format!("Run {} of {}", run.run_number, number_of_runs).white()
                    )
                    .unwrap();
                }

                if let Some(error) = &run.error {
                    let test_prefix1 = format!("{:width$}", "", width = (run_level + 1) * 3);
                    writeln!(feedback, "{}{}", test_prefix1, &error.to_string().red()).unwrap();
                } else if let Some(test_results) = &run.tests {
                    let test_prefix1 = format!("{:width$}", "", width = (run_level + 1) * 3);
                    let test_prefix2 = format!("{:width$}", "", width = (run_level + 2) * 3);
                    for result in test_results {
                        print!(
                            "{}{}",
                            test_prefix1.blue(),
                            &result.test_name.join(" ").blue()
                        );
                        if let Some(err) = &result.error {
                            writeln!(feedback, " {}", "[ERROR]".red()).unwrap();
                            writeln!(feedback, "{}{}", test_prefix2, err.red()).unwrap();
                        } else if result.success {
                            writeln!(feedback, " {}", "[PASS]".green()).unwrap();
                        } else {
                            writeln!(feedback, " {}", "[FAIL]".yellow()).unwrap();
                        }

                        if let Some(logs) = &result.logs {
                            for log in logs {
                                writeln!(feedback, "{}{}", test_prefix2, log.white().dimmed())
                                    .unwrap();
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Search for workbook with the given file name, looking at configured and default workbook
/// directories if file_name is not fully qualified
fn find_workbook(
    file_name: PathBuf,
    feedback: &mut Box<dyn Write>,
) -> Result<PathBuf, std::io::Error> {
    if file_name.is_file() {
        return Ok(file_name);
    }

    let mut base_name = file_name;

    // Ensure file_name has .apicize suffix
    let ext = base_name
        .extension()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if ext != ".apicize" {
        base_name.set_extension("apicize");
    }

    if base_name.is_file() {
        return Ok(base_name);
    }

    // See if the file is in the configured settings directory
    let mut configured_workbook_directory = PathBuf::default();
    if let Some(config_path) = config_dir() {
        let settings_file_name = config_path.join("apicize").join("settings.json");
        if Path::new(&settings_file_name).is_file() {
            match serde_json::from_reader::<File, ApicizeSettings>(File::open(&settings_file_name)?)
            {
                Ok(config) => {
                    if let Some(workbook_directory) = config.workbook_directory {
                        configured_workbook_directory =
                            PathBuf::from_str(workbook_directory.as_str()).unwrap();
                        let result = configured_workbook_directory.join(&base_name);
                        if result.is_file() {
                            return Ok(result);
                        } else {
                            writeln!(
                                feedback,
                                "{}",
                                format!(
                                    "WARNING: Unable to locate workbook in {}",
                                    result.to_string_lossy(),
                                )
                                .yellow()
                            )
                            .unwrap();
                        }
                    }
                }
                Err(err) => {
                    writeln!(
                        feedback,
                        "{}",
                        format!(
                            "WARNING [Apicize]: Unable to read Apicize settings file: {}, {}",
                            settings_file_name.to_string_lossy(),
                            err
                        )
                        .yellow()
                    )
                    .unwrap();
                }
            }
        }
    }

    // Fall back to the default Apicize documents directory
    if let Some(doc_dir) = document_dir() {
        let default_workbook_directory = doc_dir.join("apicize");
        if default_workbook_directory != configured_workbook_directory {
            let result = doc_dir.join("apicize").join(&base_name);
            if result.is_file() {
                return Ok(result);
            }

            writeln!(
                feedback,
                "{}",
                format!(
                    "WARNING: Unable to locate workbook in {}",
                    result.to_string_lossy(),
                )
                .yellow()
            )
            .unwrap();
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "Workbook not found",
    ))
}

fn process_execution(
    execution_result: &Result<ApicizeExecution, ApicizeError>,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) -> usize {
    let mut failure_count;
    match execution_result {
        Ok(execution) => {
            failure_count = 0;
            execution
                .items
                .iter()
                .for_each(|i| render_execution_item(i, 0, locale, feedback));

            writeln!(feedback).unwrap();
            writeln!(feedback).unwrap();
            writeln!(
                feedback,
                "{}",
                "--------------- Totals ---------------".white()
            )
            .unwrap();
            writeln!(
                feedback,
                "{}{}",
                "Passed Tests: ".white(),
                if execution.passed_test_count > 0 {
                    execution
                        .passed_test_count
                        .to_formatted_string(locale)
                        .green()
                } else {
                    "0".white()
                }
            )
            .unwrap();

            writeln!(
                feedback,
                "{}{}",
                "Failed Tests: ".white(),
                if execution.failed_test_count > 0 {
                    execution
                        .failed_test_count
                        .to_formatted_string(locale)
                        .yellow()
                } else {
                    "0".white()
                }
            )
            .unwrap();

            writeln!(
                feedback,
                "{}{}",
                "Requests with passed tests: ".white(),
                if execution.requests_with_passed_tests_count > 0 {
                    execution
                        .requests_with_passed_tests_count
                        .to_formatted_string(locale)
                        .green()
                } else {
                    "0".white()
                }
            )
            .unwrap();

            writeln!(
                feedback,
                "{}{}",
                "Requests with failed tests: ".white(),
                if execution.requests_with_failed_tests_count > 0 {
                    failure_count += execution.requests_with_failed_tests_count;
                    execution
                        .requests_with_failed_tests_count
                        .to_formatted_string(locale)
                        .yellow()
                } else {
                    "0".white()
                }
            )
            .unwrap();

            writeln!(
                feedback,
                "{}{}",
                "Requests with errors: ".white(),
                if execution.requests_with_errors > 0 {
                    failure_count += execution.requests_with_errors;
                    execution
                        .requests_with_errors
                        .to_formatted_string(locale)
                        .red()
                } else {
                    "0".white()
                }
            )
            .unwrap();
            writeln!(
                feedback,
                "{}",
                "--------------------------------------".white()
            )
            .unwrap();
        }
        Err(err) => {
            let padding = format!("{:width$}", "", width = level * 3);
            writeln!(
                feedback,
                "{}{}",
                padding,
                format!("{}: {}", err.get_label(), err).red()
            )
            .unwrap();
            failure_count = 1;
        }
    }

    failure_count
}

static LOGGER: OnceLock<ReqwestLogger> = OnceLock::new();
static TRACE_FILE: OnceLock<File> = OnceLock::new();

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();

    let mut send_output_to = args.output.unwrap_or(String::from(""));
    if send_output_to.to_lowercase() == "stdout" {
        send_output_to = String::from("-");
    }
    let mut feedback: Box<dyn std::io::Write> = if send_output_to == "-" {
        Box::new(stderr())
    } else {
        Box::new(stdout())
    };

    writeln!(feedback).unwrap();
    writeln!(
        feedback,
        "{}",
        "------------ Initializtion -----------".white()
    )
    .unwrap();
    writeln!(feedback).unwrap();

    let globals_filename = args
        .globals
        .map(PathBuf::from)
        .unwrap_or(Parameters::get_globals_filename());

    if args.info {
        writeln!(
            feedback,
            "Global parameters: {}",
            globals_filename.to_string_lossy()
        )
        .unwrap();
    }

    let locale = SystemLocale::default().unwrap();
    let workspace: Workspace;

    if args.file == "-" {
        let global_parameters = match Parameters::open(&globals_filename, true) {
            Ok(params) => params,
            Err(err) => {
                eprintln!("{}", format!("Unable to read STDIN: {}", err.error).red());
                process::exit(-2);
            }
        };

        match open_data_stream(String::from("STDIN"), &mut stdin()) {
            Ok(success) => {
                match Workspace::build_workspace(
                    success.data,
                    Parameters::default(),
                    global_parameters,
                ) {
                    Ok(opened_workspace) => {
                        workspace = opened_workspace;
                    }
                    Err(err) => {
                        eprintln!("{}", format!("Unable to read STDIN: {}", err.error).red());
                        process::exit(-2);
                    }
                }
            }
            Err(err) => {
                eprintln!("{}", format!("Unable to read STDIN: {}", err.error).red());
                process::exit(-2);
            }
        }
    } else {
        let file_name = match find_workbook(PathBuf::from(&args.file), &mut feedback) {
            Ok(f) => f,
            Err(err) => {
                eprintln!("{}", format!("Error: {}", &err).red());
                std::process::exit(-1);
            }
        };

        writeln!(
            feedback,
            "{}",
            format!("Opening {}", &file_name.to_string_lossy()).white()
        )
        .unwrap();

        match Workspace::open(&file_name) {
            Ok(opened_workspace) => {
                workspace = opened_workspace;
            }
            Err(err) => {
                eprintln!(
                    "{}",
                    format!("Unable to read {}: {}", err.file_name, err.error).red()
                );
                process::exit(-2);
            }
        }
    }

    if let Some(warnings) = workspace.get_warnings() {
        for warning in warnings {
            writeln!(
                feedback,
                "{}",
                format!("WARNING [Workbook]: {warning}").yellow()
            )
            .unwrap();
        }
    }
    for request in workspace.requests.entities.values() {
        if let Some(warnings) = request.get_warnings() {
            for warning in warnings {
                writeln!(
                    feedback,
                    "{}",
                    format!("WARNING [Workbook]: {warning}").yellow()
                )
                .unwrap();
            }
        }
    }

    let request_ids = workspace.requests.top_level_ids.to_owned();
    let mut output_file = OutputFile {
        runs: HashMap::new(),
    };

    let start = Instant::now();
    let mut failure_count = 0;
    let arc_test_started = Arc::new(start);

    let enable_trace: bool;
    if let Some(file_name) = args.tracing {
        let _ = log::set_logger(LOGGER.get_or_init(|| {
            ReqwestLogger::new(
                &start.clone(),
                TRACE_FILE.get_or_init(|| File::create(file_name).unwrap()),
            )
        }));
        log::set_max_level(log::LevelFilter::Trace);
        enable_trace = true;
    } else {
        enable_trace = false;
    }

    let shared_workspace = Arc::new(workspace);
    for run_number in 0..args.runs {
        let mut executions: HashMap<String, Result<ApicizeExecution, ApicizeError>> =
            HashMap::new();
        if args.runs > 1 {
            writeln!(feedback).unwrap();
            writeln!(
                feedback,
                "{}",
                format!(
                    "------- Execution Run {} of {} ---------",
                    run_number + 1,
                    args.runs
                )
                .white()
            )
            .unwrap();
            writeln!(feedback).unwrap();
        }

        for request_id in &request_ids {
            if let Some(request) = &shared_workspace.requests.entities.get(request_id) {
                let mut name = request.get_name().clone();
                if name.is_empty() {
                    name = format!("{} (Unnamed)", request.get_id());
                }

                writeln!(feedback, "{}", format!("Calling {}", name).blue()).unwrap();

                let result = test_runner::run(
                    &vec![request_id.clone()],
                    shared_workspace.clone(),
                    None,
                    arc_test_started.clone(),
                    None,
                    enable_trace,
                )
                .await;

                executions.insert(name, result);
            }
        }

        writeln!(feedback).unwrap();
        writeln!(
            feedback,
            "{}",
            "--------------- Results --------------".white()
        )
        .unwrap();

        let execution_values: Vec<Result<ApicizeExecution, ApicizeError>> =
            executions.into_values().collect();
        for execution in &execution_values {
            writeln!(feedback).unwrap();
            failure_count += process_execution(execution, 0, &locale, &mut feedback);
        }

        output_file.runs.insert(run_number, execution_values);
    }

    if !send_output_to.is_empty() {
        let serialized = serde_json::to_string(&output_file).unwrap();

        let dest: &str;
        let result = if send_output_to == "-" {
            dest = "STDOUT";
            write!(stdout(), "{}", serialized)
        } else {
            dest = send_output_to.as_str();
            fs::write(&send_output_to, serialized)
        };

        writeln!(feedback).unwrap();
        match result {
            Ok(_) => writeln!(
                feedback,
                "{}",
                format!("Test results written to {}", dest).blue()
            )
            .unwrap(),
            Err(ref err) => {
                panic!("Unable to write {} - {}", dest, err)
            }
        }
    }

    cleanup_v8();
    process::exit(failure_count as i32);
}

#[derive(Serialize)]
struct OutputFile {
    pub runs: HashMap<usize, Vec<Result<ApicizeExecution, ApicizeError>>>,
}

/// Apicize application settings
#[derive(Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
struct ApicizeSettings {
    /// Default directory that workbooks are stored in
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workbook_directory: Option<String>,
}

pub struct ReqwestLogger {
    regex_readwrite: Regex,
    regex_connect: Regex,
    start: Instant,
    output: &'static File,
}

impl ReqwestLogger {
    pub fn new(start: &Instant, output: &'static File) -> Self {
        ReqwestLogger {
            regex_readwrite: Regex::new(r#"^([0-9a-f]+) (read|write): (b".*")$"#).unwrap(),
            regex_connect: Regex::new(r#"starting new connection: (.*)"#).unwrap(),
            start: *start,
            output,
        }
    }
}

impl log::Log for ReqwestLogger {
    fn enabled(&self, _: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &Record) {
        let target = record.target();
        if target == "reqwest::connect" {
            let args = record.args().to_string();
            if let Some(result) = self.regex_connect.captures(&args) {
                if let Some(host) = result.get(1) {
                    let mut out = self.output;
                    out.write_all(
                        format!(
                            "{}ms [] (CONNECT) {}\n",
                            self.start.elapsed().as_millis(),
                            host.as_str()
                        )
                        .as_bytes(),
                    )
                    .unwrap();
                }
            }
        } else if target == "reqwest::connect::verbose" {
            let args = record.args().to_string();
            if let Some(result) = self.regex_readwrite.captures(&args) {
                if let Some(request_id) = result.get(1) {
                    if let Some(operation) = result.get(2) {
                        if let Some(data) = result.get(3) {
                            let mut out = self.output;
                            out.write_all(
                                format!(
                                    "{}ms [{}] ({}) {}\n",
                                    self.start.elapsed().as_millis(),
                                    request_id.as_str(),
                                    operation.as_str().to_uppercase(),
                                    data.as_str(),
                                )
                                .as_bytes(),
                            )
                            .unwrap();
                        }
                    }
                }
            }
        }
    }

    fn flush(&self) {}
}
