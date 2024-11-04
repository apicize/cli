use apicize_lib::apicize::{ApicizeExecution, ApicizeExecutionItem};
use apicize_lib::settings::ApicizeSettings;
use apicize_lib::{open_data_stream, test_runner, Parameters, Warnings, Workspace};
use apicize_lib::test_runner::cleanup_v8;
use clap::Parser;
use colored::Colorize;
use num_format::{SystemLocale, ToFormattedString};
use serde::Serialize;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::io::{stderr, stdin, stdout, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use std::{fs, process};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None, allow_hyphen_values = true)]
struct Args {
    /// Name of the file to process (or - to read STDIN)
    file: String,
    /// Global parameter file name (overriding default location, if available)
    #[arg(short, long)]
    globals: Option<String>,
    /// Print configuration information
    #[arg(short, long, default_value_t = false)]
    info: bool,
    /// Number of times to run workbook (runs are sequential)
    #[arg(short, long, default_value_t = 1)]
    runs: usize,
    /// Name of the output file name for test results (or - to write to STDOUT)
    #[arg(short, long)]
    output: Option<String>,
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

                if let Some(test_results) = &run.tests {
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

fn process_execution(
    execution_result: &Result<ApicizeExecution, String>,
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
            writeln!(feedback, "{}{}", padding, err.red()).unwrap();
            failure_count = 1;
        }
    }

    failure_count
}

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

    let stored_settings: Option<ApicizeSettings> = match ApicizeSettings::open() {
        Ok(serialized_settings) => Some(serialized_settings.data),
        Err(_err) => None,
    };

    let globals_filename = args.globals.map(PathBuf::from);

    if args.info {
        let global_filename = if let Some(filename) = &globals_filename {
            String::from(filename.to_string_lossy())
        } else {
            let default_globals_filename = Parameters::get_globals_filename();
            String::from(default_globals_filename.to_string_lossy())
        };

        writeln!(feedback, "Global parameters: {}", &global_filename).unwrap();

        writeln!(
            feedback,
            "Default workbooks directory: {}",
            ApicizeSettings::get_workbooks_directory().to_string_lossy()
        )
        .unwrap();
    }

    let locale = SystemLocale::default().unwrap();
    let workspace: Workspace;

    if args.file == "-" {
        match open_data_stream(String::from("STDIN"), &mut stdin()) {
            Ok(mut success) => {
                match Workspace::open_from_workbook(&mut success.data, None, globals_filename) {
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
        let mut file_name = PathBuf::from(&args.file);

        let mut found = file_name.as_path().is_file();

        // Try adding extension if not in file name
        if !found && file_name.extension() != Some(OsStr::new("apicize")) {
            file_name.set_extension("apicize");
            found = file_name.as_path().is_file();
        }

        // Try settings workbook path if defined
        if !found {
            if let Some(dir) = stored_settings.and_then(|s| s.workbook_directory) {
                let mut temp = PathBuf::from(dir);
                temp.push(&file_name);
                file_name = temp;
                found = file_name.as_path().is_file();
            }
        }

        if !found {
            eprintln!(
                "{}",
                format!("Error: Apicize file \"{}\" not found", &args.file).red()
            );
            std::process::exit(-1);
        }

        writeln!(
            feedback,
            "{}",
            format!("Opening {}", &file_name.to_string_lossy()).white()
        )
        .unwrap();

        match Workspace::open_from_file(&file_name, globals_filename) {
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

    // initialize_v8();

    let request_ids = workspace.requests.top_level_ids.to_owned();
    let mut output_file = OutputFile {
        runs: HashMap::new(),
    };

    let start = Instant::now();
    let mut failure_count = 0;
    let arc_test_started = Arc::new(start);

    let shared_workspace = Arc::new(workspace);
    for run_number in 0..args.runs {
        let mut executions: HashMap<String, Result<ApicizeExecution, String>> = HashMap::new();
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
                    shared_workspace.clone(),
                    Some(vec![request_id.clone()]),
                    None,
                    arc_test_started.clone(),
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

        let execution_values: Vec<Result<ApicizeExecution, String>> =
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
    pub runs: HashMap<usize, Vec<Result<ApicizeExecution, String>>>,
}
