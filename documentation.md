# class Surveyor
The Surveyor class is a utility class designed to perform surveys on various targets using Endpoint Detection and Response (EDR) systems. It allows users to specify the EDR system, credentials, and other survey parameters for data collection and analysis.

### Class Attributes:
- `_table_template` (Tuple[int, int, int, int, int, int]): A tuple containing the column widths for formatting tabular data during the survey.
- `_table_template_str` (str): A string representation of the table template used for formatting survey results.
- `_edr` (str): The name of the Endpoint Detection and Response (EDR) system to be used for the survey.
- `_creds` (dict): A dictionary containing EDR-specific credential parameters for authentication.
- `_prefix` (str): A string used as a prefix for the survey operation.
- `_namespace` (str): The namespace or scope of the survey.
- `_log` (logging.Logger): A logger to record the survey progress and messages.
- `_use_tqdm` (bool): A flag indicating whether to use tqdm for displaying progress during the survey.
- `_log_dir` (str): The directory where log files will be stored during the survey.
- `_results_collector`: (list): Holds collected results in a list during class operations.
- `_output_format` (str): Specifies the output format for generated or saved results (default: CSV).
- `_writer` (csv.writer): Used for writing data to the output file based on the chosen format.

### Methods:

- `__init__(self, edr: str, creds: dict)`
The constructor method for the Surveyor class.

### Parameters:
- `edr` (str): The name of the Endpoint Detection and Response (EDR) system to be used for the survey.
- `creds` (dict): A dictionary containing EDR-specific credential parameters for authentication.

### Notes:
The constructor initializes the `Surveyor `class with the specified EDR system and its corresponding credentials.
It performs validation on the supplied credentials using the `check_credentials_structure` function.
If the validation result is `True`, the attributes _edr and _creds are set to the supplied values.
If the validation result is `False`, the constructor will exit the program using `sys.exit(validation)`.

### Other Class Features:
The Surveyor class may have additional methods and features not explicitly mentioned in the provided code. These methods could include survey-related functions like data collection, processing, and analysis.

### Notes:
The `Surveyor` class is meant to be used as a utility for conducting surveys on different targets using the specified EDR system.
Users can initialize the `Surveyor` class with their EDR system name and corresponding credentials to begin the survey process.
The class may provide additional functionalities for configuring survey parameters, executing surveys, and generating survey reports.

# survey (function)
The survey method is part of the Surveyor class and is used for conducting surveys on various targets, such as systems, logs, or networks, to collect relevant data and information.

### Parameters:
- `prefix` (str, optional): A string used as a prefix for the survey operation.
- `hostname` (str, optional): The hostname of the target to be surveyed.
- `days` (int, optional): The number of days of data to survey.
- `minutes` (int, optional): The number of minutes of data to survey.
- `username` (str, optional): The username associated with the target.
- `namespace` (str, optional): The namespace or scope of the survey.
- `limit` (int, optional): The maximum number of items to include in the survey results.
- `ioc_list` (list, optional): A list of indicators of compromise (IOCs) to search for during the survey.
- `ioc_source` (str, optional): The source of the IOCs specified in ioc_list.
- `ioc_type` (str, optional): The type or category of IOCs to search for during the survey.
- `query` (str, optional): A custom query or search string to filter the survey results.
- `output` (str, optional): The output filename for the survey results (`csv`).
- `output_format` (str, optional): Specify output file format, `json` or `csv`.
- `definition` (dict, optional): A dictionary containing survey definitions. (Note: Takes in raw definition file contents)
- `definitions` (list, optional): A list of absolute paths to survey definition files. (Note: Takes in a list of absolute paths to definition files)
- `def_source` (str, optional): The source of the survey definitions specified in definitions.
- `sigma_rule` (str, optional): A single Sigma rule file to process during the survey.
- `sigma_rules_str` (str, optional): A string containing multiple Sigma rule files to process during the survey. (comma-separated)
- `sigma_rules` (list, optional): A list of Sigma rule file paths to process during the survey.
- `no_file` (bool, optional): If True, the survey will not use any file-based inputs or outputs.
- `no_progress` (bool, optional): If True, the survey progress will not be displayed during execution.
- `log` (logging.Logger, optional): A logger to record the survey progress and messages.
- `log_dir` (str, optional): The directory where log files will be stored during the survey.
- `product_args` (dict, optional): An open product_args keyword that allows supplying any keywords, which the surveyor will attempt to guess the correct EDR (Endpoint Detection and Response) to which the arguments apply.
- `raw` (bool, optional): If True, the survey results will be returned as raw data without any post-processing.

### Returns:
- `list`: A list containing the survey results.

### Notes:

The survey method initiates a survey based on the provided parameters and collects data accordingly.
Depending on the target and options selected, the survey will encompass different data sources and criteria.
The method can process different types of survey definitions, Sigma rules, or custom queries to customize the survey.
The survey results will be returned as a list, and the format of the results can be specified using the output parameter.
The log parameter can be used to provide a custom logger for recording the survey progress and messages.
The log_dir parameter specifies the directory where log files will be stored during the survey.

Example Usage:

# Create a surveyor instance

```
surveyor = Surveyor()

#Example programmatic usage of the Surveyor class

edr_name = "cbc"
credentials = {
    "url": "supersecretsecuritysite.com",
    "token": "secretpassword/1234",
    "org_key": "A1234Z",
}

surveyor = Surveyor(edr=edr_name, creds=credentials)

# Perform a survey using the initialized surveyor instance

survey_results = surveyor.survey(
    query="powershell.exe",
    limit=25,
    days=7
    )
```

In this example, Surveyor will conduct a survey on the target "supersecretsecuritysite.com" looking for powershell use over the past 7 days. It will return a maximum of 25 results.

# Surveyor via CLI:
This script is designed to conduct surveys on various targets using different Endpoint Detection and Response (EDR) systems. It allows users to customize the survey by specifying various parameters and options through command-line arguments.

Usage:

```python surveyor.py [arguments]```

Command-Line Arguments:
- `--prefix`: Output filename prefix.
- `--profile`: The credentials profile to use.
- `--days`: Number of days to search.
- `--minutes`: Number of minutes to search.
- `--limit`: Number of results to return. (Default and maximum values vary based on the EDR system)
- `--hostname`: Target specific host by name.
- `--username`: Target specific username.
- `--deffile`: Definition file to process (must end in .json).
- `--defdir`: Directory containing multiple definition files.
- `--query`: A single query to execute.
- `--iocfile`: IOC file to process. One IOC per line. (REQUIRES --ioctype)
- `--ioctype`: Type of IOCs to process. Choices: ['ipaddr', 'domain', 'md5']
- `--iocsource`: Source of the IOCs specified in --iocfile.
- `--sigmarule`: Sigma rule file to process (must be in YAML format).
- `--sigmadir`: Directory containing multiple sigma rule files.
- `--edr`: Specify the EDR to be queried. Choices: ['cbc', 'cbr', 'cortex', 'dfe', 's1']. (Required)

Optional Output Arguments:
- `--creds`: Absolute path to the credential file.
- `--output or -o`: Specify the output file for the survey results. The default is to create survey.csv in the current directory.
- `--no-file`: Write results to STDOUT instead of the output CSV.
- `--no-progress`: Suppress the progress bar.

Logging Options:
- `--log-dir`: Specify the logging directory. (Default: 'logs')

Cortex XDR Options:
(Optional - Only for Cortex XDR surveys)

- `--auth-type`: ID of SentinelOne site to query. (Default: 'standard')
- `--tenant-ids`: ID of SentinelOne account to query. (Type: list)

SentinelOne Options:
(Optional - Only for SentinelOne surveys)

- `--site-ids`: ID of SentinelOne site to query. (Type: list)
- `--account-ids`: ID of SentinelOne account to query. (Type: list)
- `--account-names`: Name of SentinelOne account to query. (Type: list)
- `--dv`: Use Deep Visibility for queries. (Action: store_true, Default: False)

VMware Carbon Black Enterprise EDR Options:
(Optional - Only for VMware Carbon Black Enterprise EDR surveys)

- `--device-group`: Name of the device group to query. (Type: list)
- `--dv`: Use Deep Visibility for queries. (Action: store_true, Default: False)
- `--device-policy`: Name of the device policy to query. (Type: list)

VMware Carbon Black Response Options:
(Optional - Only for VMware Carbon Black Response surveys)

- `--sensor-group`: Name of the sensor group to query. (Type: list)

Microsoft Defender for Endpoints Options:
(None currently available)

Notes:
This script is a command-line utility designed to perform surveys using various EDR systems based on the specified parameters.
Users can choose the EDR system (--edr) and configure survey options and parameters accordingly.
The script relies on the Surveyor class to conduct the actual surveys and collect the data.
The Surveyor class is initialized with the specified EDR system (--edr) and its corresponding credentials (--creds).
Survey parameters are built based on the provided command-line arguments using the build_survey function.
The survey results will be stored in a CSV file (default: survey.csv) or displayed on the STDOUT if the --no-file option is used.
Progress during the survey will be displayed with a progress bar by default (--no-progress suppresses it).
Example Usage:

```python surveyor.py --edr s1 --creds /path/to/credentials.ini --query "example.com" --days 7 --limit 1000 --output survey_results.csv```

In this example, the script will conduct a survey on the EDR system 's1' (SentinelOne) for the target 'example.com' for the past 7 days. It will limit the survey results to 1000 entries and store the results in the 'survey_results.csv' file. The credentials are supplied through a ini file located at '/path/to/credentials.ini'.