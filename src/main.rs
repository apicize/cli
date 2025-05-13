use apicize_lib::test_runner::cleanup_v8;
use apicize_lib::{
    open_data_stream, ApicizeError, ApicizeExecution, ApicizeExecutionType, ApicizeGroup,
    ApicizeGroupChildren, ApicizeGroupItem, ApicizeGroupRun, ApicizeRequest, ApicizeResult,
    ApicizeRowSummary, ApicizeRunner, ApicizeTestBehavior, ApicizeTestResult, ExternalData,
    ExternalDataSourceType, Identifiable, Parameters, Selection, Tallies, Tally, TestRunnerContext,
    Warnings, Workspace,
};
use clap::Parser;
use colored::Colorize;
use dirs::{config_dir, document_dir};
use log::{Metadata, Record};
use num_format::{SystemLocale, ToFormattedString};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env::current_exe;
use std::ffi::OsStr;
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
    /// Name of the output file name for tracing HTTP traffic
    #[arg(short, long)]
    trace: Option<String>,
    /// Global parameter file name (overriding default location, if available)
    #[arg(short, long)]
    globals: Option<String>,
    /// Name of seed entry, or relative path to seed file from input stream
    #[arg(short, long)]
    seed: Option<String>,
    /// Default certificate (ID or name) to use for requests
    #[arg(long)]
    default_scenario: Option<String>,
    /// Default authorization (ID or name) to use for requests
    #[arg(long)]
    default_authorization: Option<String>,
    /// Default certificate (ID or name) to use for requests
    #[arg(long)]
    default_certificate: Option<String>,
    /// Default proxy (ID or name) to use for requests
    #[arg(long)]
    default_proxy: Option<String>,
    /// If set, output will not use color
    #[arg(long, default_value_t = false)]
    no_color: bool,
    /// Print configuration information
    #[arg(long, default_value_t = false)]
    info: bool,
}

trait NumericFormat {
    fn to_min_sec_string(&self, locale: &SystemLocale) -> String;
    fn to_ms_string(&self, locale: &SystemLocale) -> String;
}

impl NumericFormat for u128 {
    fn to_min_sec_string(&self, locale: &SystemLocale) -> String {
        let mut ms = *self;
        let mins: u128 = ms / 60000;
        ms -= mins * 60000;
        let secs: u128 = ms / 1000;
        ms -= secs * 1000;
        format!("{:02}:{:02}{}{:03}", mins, secs, locale.decimal(), ms)
    }

    fn to_ms_string(&self, locale: &SystemLocale) -> String {
        format!("{:00} ms", self.to_formatted_string(locale))
    }
}

trait FormatHelper {
    fn prefix(level: usize) -> Self;
    fn title(title: &str) -> Self;
}

impl FormatHelper for String {
    fn prefix(level: usize) -> String {
        format!("{:width$}", "", width = level * 3)
    }

    fn title(title: &str) -> String {
        let t = if title.is_empty() {
            String::new()
        } else {
            format!(" {} ", title)
        };
        format!("{:-^1$}", t, 32)
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

fn render_group(
    group: &ApicizeGroup,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    writeln!(
        feedback,
        "{}",
        format!(
            "{}{} ({} - {})",
            String::prefix(level),
            &group.name,
            group.executed_at.to_min_sec_string(locale),
            group.duration.to_ms_string(locale)
        )
        .white()
    )
    .unwrap();

    if let Some(children) = &group.children {
        match children {
            ApicizeGroupChildren::Items(children) => {
                for item in &children.items {
                    render_item(item, level + 1, locale, feedback);
                }
            }
            ApicizeGroupChildren::Runs(runs) => {
                render_group_runs(&runs.items, level + 1, locale, feedback)
            }
        }
    }

    // render_tallies(
    //     &group.get_tallies(),
    //     format!("{} Totals", &group.name).as_str(),
    //     level,
    //     locale,
    //     feedback,
    // );
}

fn render_row_summary(
    summary: &ApicizeRowSummary,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    let row_count = summary.rows.len();
    let prefix = String::prefix(level);

    for row in &summary.rows {
        writeln!(
            feedback,
            "{}",
            format!("{}Row {} of {}", prefix, row.row_number, row_count).white()
        )
        .unwrap();

        for item in &row.items {
            render_item(item, level + 1, locale, feedback);
        }

        writeln!(feedback).unwrap();
        render_tallies(
            &row.get_tallies(),
            &format!("Row {} Totals", row.row_number),
            level,
            locale,
            feedback,
        );
        writeln!(feedback).unwrap();
    }

    // render_tallies(
    //     &summary.get_tallies(),
    //     "All Row Totals",
    //     level,
    //     locale,
    //     feedback,
    // );
}

fn render_item(
    item: &ApicizeGroupItem,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    match item {
        ApicizeGroupItem::Group(group) => render_group(group, level, locale, feedback),
        ApicizeGroupItem::Request(request) => render_request(request, level, locale, feedback),
    }
}

fn render_group_runs(
    group_runs: &Vec<ApicizeGroupRun>,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    let prefix = String::prefix(level);
    let count = group_runs.len();

    for run in group_runs {
        writeln!(
            feedback,
            "{}",
            format!("{} Run {} of {}", &prefix, run.run_number, &count).white()
        )
        .unwrap();

        for child in &run.children {
            render_item(child, level + 1, locale, feedback);
        }

        // render_tallies(
        //     &group_runs.get_tallies(),
        //     format!("Run #{} Totals", run.run_number).as_str(),
        //     level,
        //     locale,
        //     feedback,
        // );
    }
}

fn render_request(
    request: &ApicizeRequest,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    writeln!(
        feedback,
        "{}",
        format!("{}{}", String::prefix(level), &request.name).white()
    )
    .unwrap();

    match &request.execution {
        ApicizeExecutionType::None => {}
        ApicizeExecutionType::Single(execution) => {
            render_execution(execution, level, locale, feedback);
        }
        ApicizeExecutionType::Runs(executions) => {
            let count = executions.items.len();
            let mut run_number = 0;
            for execution in &executions.items {
                run_number += 1;
                writeln!(
                    feedback,
                    "{}",
                    format!("{}Run {} of {}", String::prefix(level), &run_number, &count).white()
                )
                .unwrap();
                render_execution(execution, level + 1, locale, feedback);
            }
        }
    }
}

fn render_execution(
    execution: &ApicizeExecution,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    match &execution.error {
        Some(err) => {
            writeln!(
                feedback,
                "{}{}",
                &String::prefix(level + 1),
                err.to_string().red()
            )
            .unwrap();
        }
        None => {
            if let Some(tests) = &execution.tests {
                render_test_results(tests, level + 1, locale, feedback);
            }
        }
    }
}

fn render_behavior(
    behavior: &ApicizeTestBehavior,
    level: usize,
    feedback: &mut Box<dyn Write>,
    name_prefix: Option<&str>,
) {
    let prefix = String::prefix(level);
    let full_name = match name_prefix {
        Some(scenario_name) => format!("{} {}", scenario_name, behavior.name),
        None => behavior.name.to_string(),
    };

    writeln!(
        feedback,
        "{}{} {}",
        &prefix,
        full_name.bright_blue(),
        if behavior.error.is_some() {
            "[ERROR]".red()
        } else if behavior.success {
            "[PASS]".green()
        } else {
            "[FAIL]".red()
        }
    )
    .unwrap();

    if let Some(error) = &behavior.error {
        let prefix1 = format!("{:width$}", "", width = (level + 1) * 3);
        writeln!(feedback, "{}{}", prefix1, error.red()).unwrap();
    }

    if let Some(logs) = &behavior.logs {
        let prefix1 = format!("{:width$}", "", width = (level + 1) * 3);
        for log in logs {
            writeln!(feedback, "{}{}", prefix1, log.white().dimmed()).unwrap();
        }
    }
}

fn render_test_results(
    results: &Vec<ApicizeTestResult>,
    level: usize,
    _locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    let prefix = String::prefix(level);
    for result in results {
        match result {
            ApicizeTestResult::Scenario(scenario) => {
                if let Some(children) = &scenario.children {
                    if children.len() == 1 {
                        if let ApicizeTestResult::Behavior(behavior) = children.first().unwrap() {
                            render_behavior(behavior, level, feedback, Some(&scenario.name));
                            continue;
                        }
                    }

                    writeln!(
                        feedback,
                        "{}{} {}",
                        &prefix,
                        scenario.name.bright_blue(),
                        if scenario.success {
                            "[PASS]".green()
                        } else {
                            "[FAIL]".red()
                        }
                    )
                    .unwrap();

                    render_test_results(children, level + 1, _locale, feedback);
                }
            }
            ApicizeTestResult::Behavior(behavior) => {
                render_behavior(behavior, level, feedback, None);
            }
        }
    }
}

fn render_tallies(
    tallies: &Tallies,
    title: &str,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    let prefix = String::prefix(level);
    writeln!(feedback, "{}{}", &prefix, String::title(title).white()).unwrap();

    writeln!(
        feedback,
        "{}{}{}",
        &prefix,
        "Successful Requests: ".white(),
        if tallies.request_success_count > 0 {
            tallies
                .request_success_count
                .to_formatted_string(locale)
                .green()
        } else {
            "0".white()
        }
    )
    .unwrap();

    writeln!(
        feedback,
        "{}{}{}",
        &prefix,
        "Failed Requests: ".white(),
        if tallies.request_failure_count > 0 {
            tallies
                .request_failure_count
                .to_formatted_string(locale)
                .yellow()
        } else {
            "0".white()
        }
    )
    .unwrap();

    writeln!(
        feedback,
        "{}{}{}",
        &prefix,
        "Errors: ".white(),
        if tallies.request_error_count > 0 {
            tallies
                .request_error_count
                .to_formatted_string(locale)
                .red()
        } else {
            "0".white()
        }
    )
    .unwrap();

    writeln!(
        feedback,
        "{}{}{}",
        &prefix,
        "Passed Tests: ".white(),
        if tallies.test_pass_count > 0 {
            tallies.test_pass_count.to_formatted_string(locale).green()
        } else {
            "0".white()
        }
    )
    .unwrap();

    writeln!(
        feedback,
        "{}{}{}",
        &prefix,
        "Failed Tests: ".white(),
        if tallies.test_fail_count > 0 {
            tallies.test_fail_count.to_formatted_string(locale).yellow()
        } else {
            "0".white()
        }
    )
    .unwrap();

    writeln!(feedback, "{}{}", &prefix, String::title("").white()).unwrap();
}

static LOGGER: OnceLock<ReqwestLogger> = OnceLock::new();
static TRACE_FILE: OnceLock<File> = OnceLock::new();

/// Return matching selection (if any)
fn find_selection<T: Identifiable>(
    requested_selection: &Option<String>,
    entities: &HashMap<String, T>,
    label: &str,
) -> Option<Selection> {
    if let Some(selection) = requested_selection {
        let matching: Option<&T> = entities.iter().find_map(|(id, e)| {
            if id == selection || e.get_name() == selection {
                Some(e)
            } else {
                None
            }
        });

        if let Some(e) = matching {
            Some(Selection {
                id: e.get_id().to_owned(),
                name: "".to_string(),
            })
        } else {
            eprintln!(
                "{}",
                format!("Unable to locate {} \"{}\"", label, selection).red()
            );
            process::exit(-3);
        }
    } else {
        None
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args = Args::parse();

    if args.no_color {
        colored::control::set_override(false);
    }

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
    writeln!(feedback, "{}", String::title("Initialization").white()).unwrap();
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

    if let Some(trace_file_name) = &args.trace {
        writeln!(feedback, "Trace HTTP : {}", trace_file_name).unwrap();
    }

    let locale = SystemLocale::default().unwrap();
    let mut workspace: Workspace;
    let allowed_data_path;

    if args.file == "-" {
        allowed_data_path = current_exe().unwrap();
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

        allowed_data_path = std::path::absolute(&file_name)
            .unwrap()
            .parent()
            .unwrap()
            .to_path_buf();

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

    let enable_trace: bool;
    if let Some(file_name) = args.trace {
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

    if let Some(selection) = find_selection(
        &args.default_scenario,
        &workspace.scenarios.entities,
        "scenario",
    ) {
        workspace.defaults.selected_scenario = Some(selection);
    }

    if let Some(selection) = find_selection(
        &args.default_authorization,
        &workspace.authorizations.entities,
        "authorization",
    ) {
        workspace.defaults.selected_authorization = Some(selection);
    }

    if let Some(selection) = find_selection(
        &args.default_certificate,
        &workspace.certificates.entities,
        "certificate",
    ) {
        workspace.defaults.selected_certificate = Some(selection);
    }

    if let Some(selection) =
        find_selection(&args.default_proxy, &workspace.proxies.entities, "proxy")
    {
        workspace.defaults.selected_certificate = Some(selection);
    }

    // If seed is specified, then match by ID or name
    if let Some(seed) = args.seed {
        if let Some(id) = workspace.data.iter().find_map(|d| {
            if d.id == seed || d.name == seed {
                Some(d.id.clone())
            } else {
                None
            }
        }) {
            writeln!(feedback, "Using seed entry \"{}\"", seed.white()).unwrap();

            workspace.defaults.selected_data = Some(Selection {
                id,
                name: "Command line seed".to_string(),
            });
        } else {
            let full_seed_name = allowed_data_path.join(&seed);
            if full_seed_name.is_file() {
                writeln!(
                    feedback,
                    "{}",
                    format!("Using seed entry \"{}\"", &seed).white()
                )
                .unwrap();

                let ext = full_seed_name
                    .extension()
                    .unwrap_or(OsStr::new(""))
                    .to_string_lossy()
                    .to_ascii_lowercase();
                let source_type = match ext.as_str() {
                    "json" => ExternalDataSourceType::FileJSON,
                    "csv" => ExternalDataSourceType::FileCSV,
                    _ => {
                        eprintln!(
                            "{}",
                            format!(
                                "Error: seed file \"{}\" does not end with .csv or .json",
                                seed
                            )
                            .red()
                        );
                        std::process::exit(-1);
                    }
                };

                workspace.data.insert(
                    0,
                    ExternalData {
                        id: "\0".to_string(),
                        name: String::default(),
                        source_type,
                        source: seed,
                    },
                );

                workspace.defaults.selected_data = Some(Selection {
                    id: "\0".to_string(),
                    name: "Command line seed".to_string(),
                });
            } else {
                eprintln!("{}", format!("Error: seed \"{}\" not found", seed).red());

                std::process::exit(-1);
            }
        }
    }

    // let shared_workspace = Arc::new(workspace);
    let runner = Arc::new(TestRunnerContext::new(
        workspace,
        None,
        None,
        &Some(allowed_data_path),
        enable_trace,
    ));

    let mut level = 0;

    if args.runs == 1 {
        writeln!(feedback).unwrap();
        writeln!(feedback, "{}", String::title("Executing Requests").white()).unwrap();
        writeln!(feedback).unwrap();
    }

    let mut grand_total_tallies = Tallies::default();

    for run_number in 0..args.runs {
        let run_result = runner.run(&request_ids).await;

        if args.runs > 1 {
            writeln!(feedback).unwrap();
            writeln!(
                feedback,
                "{}",
                String::title(format!("Run #{}", &run_number).as_str()).white()
            )
            .unwrap();
            writeln!(feedback).unwrap();
            level += 1;
        }

        match &run_result {
            Ok(result) => {
                grand_total_tallies.add(&result.get_tallies());

                match result {
                    ApicizeResult::Items(items) => {
                        for item in &items.items {
                            render_item(item, level + 1, &locale, &mut feedback);
                        }
                    }
                    ApicizeResult::Rows(row_summary) => {
                        render_row_summary(row_summary, level + 1, &locale, &mut feedback);
                    }
                }
            }
            Err(err) => {
                eprintln!("{}", format!("Error: {}", err).red());
                failure_count += 1;
            }
        }

        output_file.runs.insert(run_number, run_result);
    }

    writeln!(feedback).unwrap();
    render_tallies(
        &grand_total_tallies,
        "Grand Total",
        0,
        &locale,
        &mut feedback,
    );

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
    process::exit(failure_count);
}

#[derive(Serialize)]
struct OutputFile {
    pub runs: HashMap<usize, Result<ApicizeResult, ApicizeError>>,
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
