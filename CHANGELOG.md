# Change Log

## 0.35.0

* Support insertion of non-string data in JSON body payloads
* Add row and run number to execution progress callback
* Add output variables to JSON and CSV reporting

## 0.34.0

* Added --filter argument
* Removed deprecated --report and --format arguments

## 0.33.0

* Added MacOS support

## 0.32.0

* Add password support
* Fix report rendering on request errors

## 0.31.1

* Include child exec ctrs for multi-run requests
* Add explicit param value to set (default or none) for missing parameters
* Recursively delete indexed entries with children

## 0.30.0

* Update loaded parameters to be explicitly default instead of using Option

## 0.29.2

* Fix CSV output

## 0.29.1

* Performance optimizatino

## 0.28.0

* Add disabled flag to requests/groups

## 0.27.0

* Performance optimizations

## 0.26.0

* Fix PATCH calls

## 0.25.0

* Support apicize_lib updated statndardized validations
* Remove Microsoft Trusted Signature since they stopped individual developer support

## 0.24.0

* Add --validate argument

## 0.23.2

* Add Windows MSI installer

## 0.23.1

* Support setting request and group runs to zero

## 0.23.0

* Remove Zephyr report format

## 0.22.0

* Support Key property for requests and groups, add to reporting

## 0.21.5

* Fix Zephyr report to say "Passed" instead of "Success"

## 0.21.4

* Throw error if invalid property specified in tag handlebar

## 0.21.3

* Allow handlebars in tag names to pull in values (data, scenario, output)

## 0.21.2

* Update Zephyr output to only include tagged entries

## 0.21.1

* Include method along with in execution results

## 0.21.0

* Add "tag" test function to store tag with executed tests
* Include URL and tag in execution results
* Add --report_* arguments in favor of deprecated --report/--format arguments
* Add simplified Zephyr output

## 0.20.2

* Update jp to return arrays

## 0.20.1

* Test framework: Add body type and refine $ values

## 0.20.0

* Support keep alive, allow invalid certs and number of redirect options

## 0.19.2

* Add substitution to test text
* Fix populating form data

## 0.19.1

* Fix report functionality

## 0.19.0

* Add report (JSON and CSV) functionality

## 0.18.0

* Restore warning (parameter selection) functionality

## 0.17.0

* Use updated Apicize lib that includes support for per-request/group data

## 0.16.0

* Return test results as a hierarchy of scenarios/behaviors

## 0.15.3

* Include updated lib to standardize request/response body info so that `text` is the data that is sent and `data` is a parsed value and improve XML support

## 0.15.2

* Include updated lib to prioritize scenario and data variables over previous run results

## 0.15.1

* Fixed --seed parameter to properly use relative file name

## 0.15.0

* Updated to use recent Apicize rust library

## 0.14.0

* Add support for Seed data

## 0.13.1

* Add support for default parameter CLI arguments

## 0.13.0

* Add support for reqwest trace logging

## 0.12.0

* Update apicize_lib to 0.13..3
* Fix error formatting on failed calls

## 0.11.0

* Update apicize_lib to 0.12.0

## 0.10.1

* Updated aplicize_lib to 0.11.0

## 0.9.0

* Initial break from monorepo