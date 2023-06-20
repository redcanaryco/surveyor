# Surveyor

Surveyor is a Python utility that queries Endpoint Detection and Response (EDR)
products and summarizes the results. Security and IT teams can use Surveyor to
baseline their environments and identify abnormal activity.

## Current Version: 2.4

Version 2.0 introduced breaking changes to the command line interface and support for SentinelOne. 
If you are looking for the prior version of Surveyor, see [past releases](https://github.com/redcanaryco/surveyor/releases).

If you are new to version 2.X please see the [Getting started](https://github.com/redcanaryco/surveyor/wiki/Getting-started) page of the wiki
and explore the new command line interface via `surveyor.py --help`.

## Analyze your endpoints

Surveyor uses both definition files and pre-built queries to run searches across
an environment and provide insights into what applications or activities exist
within an enterprise, who is using them, and how.

Surveyor currently supports the following EDR platforms:

- Cortex XDR
- Microsoft Defender for Endpoint
- SentinelOne
- VMware Carbon Black EDR (formerly Carbon Black Response)
- VMware Carbon Black Cloud Enterprise EDR (formerly Carbon Black Cloud Threat Hunter)

You can find out more about Surveyor from [this blog post](https://redcanary.com/blog/carbon-black-response-how-tos-surveyor/).

## Get started

For information about installing and using Surveyor, see the [Getting started](https://github.com/redcanaryco/surveyor/wiki/Getting-started)
page of the wiki. Surveyor requires Python 3.9+.

## Contribute to Surveyor

We encourage and welcome your contributions to Surveyor. For more information,
see the [Contributing to Surveyor](https://github.com/redcanaryco/surveyor/wiki/Contributing-to-Surveyor)
page of the wiki.

## Query Samples

#### Running the `sysinternals` definition file using the `cbr` product:

```
surveyor.py --deffile sysinternals cbr
```

#### Running the `sysinternals` definition file using the `dfe` product:

```
surveyor.py --deffile sysinternals dfe --creds dfe_creds.ini
```