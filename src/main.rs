use apicize_lib::test_runner::cleanup_v8;
use apicize_lib::{
    ApicizeError, ApicizeExecution, ApicizeGroupResult, ApicizeGroupResultContent,
    ApicizeGroupResultRow, ApicizeGroupResultRowContent, ApicizeGroupResultRun,
    ApicizeRequestResult, ApicizeRequestResultContent, ApicizeRequestResultRow,
    ApicizeRequestResultRun, ApicizeResult, ApicizeRunner, ApicizeTestBehavior,
    ExecutionReportFormat, ExecutionResultBuilder, ExecutionResultSummary, Parameters, Tallies,
    Tally, TestRunnerContext, Warnings, Workspace,
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
use std::fs::File;
use std::io::{stderr, stdout, Write};
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
    #[arg(long, default_value_t = 1)]
    runs: usize,
    /// Name of the output file name for test results (or - to write to STDOUT)
    #[arg(short, long)]
    output: Option<String>,
    /// File name for JSON report
    #[arg(long)]
    report_json: Option<String>,
    /// File name for CSV report
    #[arg(long)]
    report_csv: Option<String>,
    /// Name of the report file name (DEPRECATED - use report_* arguments instead)
    #[arg(short, long)]
    report: Option<String>,
    /// Format of output file (DEPRECATED - use report_* arguments instead)
    #[arg(short, long, default_value("json"), value_parser(["csv","json"]))]
    format: String,
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
    /// If set, the script and arguments will be validated but tests will not be run
    #[arg(long, default_value_t = false)]
    validate: bool,
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
            format!(" {title} ")
        };
        format!("{:-^1$}", t, 40)
    }
}

/// Search for workbook with the given file name, looking at configured and default workbook
/// directories if file_name is not fully qualified
fn find_workbook(
    file_name: PathBuf,
    feedback: &mut Box<dyn Write>,
) -> Result<PathBuf, ApicizeError> {
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
            let f = File::open(&settings_file_name).map_err(|err| {
                ApicizeError::from_io(err, Some(settings_file_name.to_string_lossy().to_string()))
            })?;
            match serde_json::from_reader::<File, ApicizeSettings>(f) {
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

    Err(ApicizeError::Error {
        description: "Workbook not found".to_string(),
    })
}

fn render_results(
    results: &Vec<ApicizeResult>,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    for result in results {
        render_result(result, level, locale, feedback);
    }
}

fn render_result(
    result: &ApicizeResult,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    match result {
        ApicizeResult::Request(request) => render_request(request, level, locale, feedback),
        ApicizeResult::Group(group) => render_group(group, level, locale, feedback),
    }
}

fn render_group(
    group: &ApicizeGroupResult,
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

    match &group.content {
        ApicizeGroupResultContent::Rows { rows } => {
            render_group_rows(rows, level, locale, feedback)
        }
        ApicizeGroupResultContent::Runs { runs } => {
            render_group_runs(runs, level, locale, feedback)
        }
        ApicizeGroupResultContent::Results { results: entries } => {
            render_results(entries, level + 1, locale, feedback)
        }
    }
}

fn render_request(
    request: &ApicizeRequestResult,
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
            &request.name,
            request.executed_at.to_min_sec_string(locale),
            request.duration.to_ms_string(locale)
        )
        .white()
    )
    .unwrap();

    match &request.content {
        ApicizeRequestResultContent::Rows { rows } => render_request_rows(rows, level, feedback),
        ApicizeRequestResultContent::Runs { runs } => render_request_runs(runs, level, feedback),
        ApicizeRequestResultContent::Execution { execution } => {
            render_execution(execution, level, feedback)
        }
    }
}

fn render_group_rows(
    rows: &Vec<ApicizeGroupResultRow>,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    let count = rows.len();
    for row in rows {
        render_group_row(row, count, level + 1, locale, feedback);
    }
}

fn render_group_row(
    row: &ApicizeGroupResultRow,
    row_count: usize,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    let prefix = String::prefix(level);

    writeln!(
        feedback,
        "{}",
        format!("{}Row {} of {}", &prefix, row.row_number, &row_count).white()
    )
    .unwrap();

    // let count;
    match &row.content {
        ApicizeGroupResultRowContent::Runs { runs } => {
            // count = runs.len();
            render_group_runs(runs, level + 1, locale, feedback)
        }
        ApicizeGroupResultRowContent::Results { results: entries } => {
            // count = entries.len();
            render_results(entries, level + 1, locale, feedback)
        }
    }

    // if count > 1 {
    //     render_tallies(
    //         &row.get_tallies(),
    //         format!("Row #{} Totals", row.row_number).as_str(),
    //         level,
    //         locale,
    //         feedback,
    //     );
    // }
}

fn render_request_rows(
    rows: &Vec<ApicizeRequestResultRow>,
    level: usize,
    feedback: &mut Box<dyn Write>,
) {
    let count = rows.len();
    for row in rows {
        render_request_row(row, count, level + 1, feedback);
    }
}

fn render_request_row(
    row: &ApicizeRequestResultRow,
    row_count: usize,
    level: usize,
    feedback: &mut Box<dyn Write>,
) {
    let prefix = String::prefix(level);

    writeln!(
        feedback,
        "{}",
        format!("{} Row {} of {}", &prefix, row.row_number, &row_count).white()
    )
    .unwrap();

    match &row.results {
        apicize_lib::ApicizeRequestResultRowContent::Runs(runs) => {
            render_request_runs(runs, level, feedback)
        }
        apicize_lib::ApicizeRequestResultRowContent::Execution(execution) => {
            render_execution(execution, level, feedback)
        }
    }

    // render_tallies(
    //     &row.get_tallies(),
    //     format!("Row #{} Totals", row.row_number).as_str(),
    //     level,
    //     locale,
    //     feedback,
    // );
}

fn render_group_runs(
    runs: &Vec<ApicizeGroupResultRun>,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    let run_count = runs.len();
    for run in runs {
        render_group_run(run, run_count, level + 1, locale, feedback);
    }
}
fn render_group_run(
    run: &ApicizeGroupResultRun,
    run_count: usize,
    level: usize,
    locale: &SystemLocale,
    feedback: &mut Box<dyn Write>,
) {
    let prefix = String::prefix(level);
    writeln!(
        feedback,
        "{}",
        format!("{}Run {} of {}", &prefix, run.run_number, &run_count).white()
    )
    .unwrap();

    for result in &run.results {
        render_result(result, level + 1, locale, feedback);
    }

    // if run.results.len() > 1 {
    //     render_tallies(
    //         &run.results.get_tallies(),
    //         format!("Run #{} Totals", run.run_number).as_str(),
    //         level,
    //         locale,
    //         feedback,
    //     );
    // }
}

fn render_request_runs(
    runs: &Vec<ApicizeRequestResultRun>,
    level: usize,
    feedback: &mut Box<dyn Write>,
) {
    let run_count = runs.len();
    for run in runs {
        render_request_run(run, run_count, level + 1, feedback);
    }
}
fn render_request_run(
    run: &ApicizeRequestResultRun,
    run_count: usize,
    level: usize,
    feedback: &mut Box<dyn Write>,
) {
    let prefix = String::prefix(level);

    writeln!(
        feedback,
        "{}",
        format!("{} Run {} of {}", &prefix, run.run_number, &run_count).white()
    )
    .unwrap();

    render_execution(&run.execution, level + 1, feedback);

    // render_test_results(results, level, locale, feedback);
    // render_item(child, level + 1, locale, feedback);

    // render_tallies(
    //     &group_runs.get_tallies(),
    //     format!("Run #{} Totals", run.run_number).as_str(),
    //     level,
    //     locale,
    //     feedback,
    // );
}

fn render_execution(execution: &ApicizeExecution, level: usize, feedback: &mut Box<dyn Write>) {
    let method = match &execution.method {
        Some(m) => format!("{m} "),
        None => "".to_string(),
    };
    if let Some(url) = &execution.url {
        writeln!(
            feedback,
            "{}{}{}",
            &String::prefix(level + 1),
            method.cyan(),
            url.cyan(),
        )
        .unwrap();
    }
    match &execution.error {
        Some(err) => {
            writeln!(
                feedback,
                "{}{}",
                &String::prefix(level + 2),
                err.to_string().red()
            )
            .unwrap();
        }
        None => {
            if let Some(tests) = &execution.tests {
                render_test_results(tests, level + 1, &Vec::new(), feedback);
            }
        }
    }
}

fn render_behavior(
    behavior: &ApicizeTestBehavior,
    level: usize,
    parents: &[String],
    feedback: &mut Box<dyn Write>,
) {
    let prefix = String::prefix(level);
    let mut all_parts = Vec::from(parents);
    all_parts.push(behavior.name.clone());
    let full_name = all_parts.join(" ");

    let tag = match &behavior.tag {
        Some(t) => format!(" ({t})"),
        None => "".to_string(),
    };

    writeln!(
        feedback,
        "{}{}{} {}",
        &prefix,
        full_name.bright_blue(),
        tag.white(),
        // if behavior.error.is_some() {
        //     if let Some(err) = &behavior.error {
        //         println!("Error: {err}");
        //     }
        //     "[ERROR]".red()
        // }
        if behavior.success {
            "[PASS]".green()
        } else {
            "[FAIL]".yellow()
        }
    )
    .unwrap();

    if let Some(error) = &behavior.error {
        let prefix1 = format!("{:width$}", "", width = (level + 1) * 3);
        writeln!(feedback, "{}{}", prefix1, error.yellow()).unwrap();
    }

    if let Some(logs) = &behavior.logs {
        let prefix1 = format!("{:width$}", "", width = (level + 1) * 3);
        for log in logs {
            writeln!(feedback, "{}{}", prefix1, log.white().dimmed()).unwrap();
        }
    }
}

fn render_test_results(
    results: &Vec<ApicizeTestBehavior>,
    level: usize,
    parents: &[String],
    feedback: &mut Box<dyn Write>,
) {
    for result in results {
        render_behavior(result, level, parents, feedback);
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
    let init_title = if args.validate {
        "Initialization (Validate Only)"
    } else {
        "Initialization"
    };
    writeln!(feedback, "{}", String::title(init_title).white()).unwrap();
    writeln!(feedback).unwrap();

    let globals_filename = args
        .globals
        .map(PathBuf::from)
        .unwrap_or(Parameters::get_globals_filename());

    if args.info {
        writeln!(
            feedback,
            "{}{}",
            "Global parameters: ".white(),
            globals_filename.to_string_lossy().blue(),
        )
        .unwrap();
    }

    let locale = SystemLocale::default().unwrap();
    let mut allowed_data_path = PathBuf::default();

    let result: Result<Workspace, ApicizeError> = if args.file == "-" {
        allowed_data_path = current_exe().unwrap();
        writeln!(feedback, "{}{}", "Piping in ".white(), "STDIN".blue()).unwrap();

        Workspace::open(
            None,
            args.default_scenario,
            args.default_authorization,
            args.default_certificate,
            args.default_proxy,
            args.seed,
            &allowed_data_path,
        )
    } else {
        match find_workbook(PathBuf::from(&args.file), &mut feedback) {
            Ok(file_name) => {
                allowed_data_path = std::path::absolute(&file_name)
                    .unwrap()
                    .parent()
                    .unwrap()
                    .to_path_buf();
                writeln!(
                    feedback,
                    "{}{}",
                    "Opening ".white(),
                    file_name.to_string_lossy().blue()
                )
                .unwrap();
                Workspace::open(
                    Some(&file_name),
                    args.default_scenario,
                    args.default_authorization,
                    args.default_certificate,
                    args.default_proxy,
                    args.seed,
                    &allowed_data_path,
                )
            }
            Err(err) => Err(err),
        }
    };

    let workspace = match result {
        Ok(opened_workspace) => opened_workspace,
        Err(err) => {
            eprintln!("{}", err.to_string().red());
            process::exit(-2);
        }
    };

    if let Some(warnings) = workspace.defaults.get_warnings() {
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

    if let Some(trace_file_name) = &args.trace {
        writeln!(
            feedback,
            "{}{}",
            "Trace HTTP: ".white(),
            trace_file_name.blue(),
        )
        .unwrap();
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

    if args.validate {
        writeln!(feedback, "{}", "Workbook file appears valid".green()).unwrap();
    } else {
        // let shared_workspace = Arc::new(workspace);
        let runner = Arc::new(TestRunnerContext::new(
            workspace,
            None,
            false,
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
            let run_results = runner.run(request_ids.clone()).await;

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

            for run_result in &run_results {
                match &run_result {
                    Ok(result) => {
                        let tallies = result.get_tallies();
                        failure_count = failure_count
                            + tallies.request_failure_count
                            + tallies.request_error_count;
                        grand_total_tallies.add(&tallies);
                        render_result(result, level, &locale, &mut feedback);
                    }
                    Err(err) => {
                        eprintln!("{}", format!("Error: {err}").red());
                        failure_count += 1;
                    }
                }
            }
            output_file.runs.insert(run_number, run_results);
        }

        if !send_output_to.is_empty() {
            writeln!(feedback).unwrap();
            let serialized = serde_json::to_string(&output_file).unwrap();

            let dest: &str;
            let result = if send_output_to == "-" {
                dest = "STDOUT";
                write!(stdout(), "{serialized}")
            } else {
                dest = send_output_to.as_str();
                fs::write(&send_output_to, serialized)
            };

            writeln!(feedback).unwrap();
            match result {
                Ok(_) => writeln!(feedback, "Test results written to {}", dest.blue()).unwrap(),
                Err(ref err) => {
                    panic!("Unable to write {dest} - {err}")
                }
            }
        }

        let mut report_json = args.report_json;
        let mut report_csv = args.report_csv;

        // Map deprecated --report arguments
        if let Some(report) = &args.report {
            writeln!(
                feedback,
                "{}",
                "Warning:  --report/--format are deprecated, use --report_* arguments instead"
                    .yellow()
            )
            .unwrap();
            match args.format.as_str() {
                "json" => report_json = Some(report.clone()),
                "csv" => report_csv = Some(report.clone()),
                _ => panic!("Invalid report format \"{}\"", args.format),
            }
        }

        if report_json.is_some() || report_csv.is_some() {
            writeln!(feedback).unwrap();

            let all_summaries = output_file
                .runs
                .into_iter()
                .map(|(run_number, results)| {
                    let mut builder = ExecutionResultBuilder::new(&runner);
                    for result in results.into_iter().flatten() {
                        builder.assemble(result);
                    }
                    let (combined, _) = builder.get_results();
                    (run_number + 1, combined)
                })
                .collect::<HashMap<usize, Vec<ExecutionResultSummary>>>();

            let mut write_report = |filename: &str, format: ExecutionReportFormat| {
                match Workspace::generate_multirun_report(&all_summaries, &format) {
                    Ok(generated_report) => match fs::write(filename, &generated_report) {
                        Ok(_) => writeln!(
                            feedback,
                            "{} report written to {}",
                            format!("{format}").white(),
                            filename.blue()
                        )
                        .unwrap(),
                        Err(ref err) => {
                            panic!("Unable to write {format}, report to {filename} - {err}",)
                        }
                    },
                    Err(err) => {
                        panic!("Unable to generate {format} report - {err}");
                    }
                }
            };

            if let Some(report_filename) = report_json {
                write_report(&report_filename, ExecutionReportFormat::JSON);
            }

            if let Some(report_filename) = report_csv {
                write_report(&report_filename, ExecutionReportFormat::CSV);
            }
        }

        writeln!(feedback).unwrap();
        render_tallies(
            &grand_total_tallies,
            "Grand Total",
            0,
            &locale,
            &mut feedback,
        );

        cleanup_v8();
    }

    process::exit(failure_count.try_into().unwrap_or(-1));
}

#[derive(Serialize)]
struct OutputFile {
    pub runs: HashMap<usize, Vec<Result<ApicizeResult, ApicizeError>>>,
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
