# rialto-ocdm

## Project webpage:
https://rdkcentral.github.io/rialto-ocdm/

## Coding Guidelines:
https://wiki.rdkcentral.com/display/ASP/Rialto+Coding+Guidelines

## Commit message template:
https://wiki.rdkcentral.com/display/ASP/Commit+message+template

## Building and Running Unit Tests:
https://wiki.rdkcentral.com/display/ASP/Unit+Tests

### CI dependency and coverage selection
Unit-test and Valgrind workflows share [scripts/select_rialto_ref.sh](scripts/select_rialto_ref.sh).
OCDM `release/v0.10.0` uses Rialto `d7c1221bf9f39615177bc0cbe2cdc44e62156f36`
from the 8.6.3.0 platform manifest; `release/v0.9.3` uses
`ed056254aed65af575aa0f44fdf5a44aed992952` from the 8.4.4.0 manifest.
Other targets try the matching Rialto feature branch and then the target branch.
Missing mappings or remote lookup errors fail explicitly.

The native-build workflow uses the same Rialto selector and installs
`libyaml-cpp-dev`. Build output is shown in the job log and saved in the
`Output Logs` artifact on failure.

Master PRs retain the existing successful-master coverage artifact lookup.
Release/support PRs build the exact target commit in a separate directory with
the same Rialto ref as the PR, generating both reports in the current run.
No manual baseline run is required. Line or function coverage regressions,
baseline build failures, and missing or invalid statistics fail the check.
Push/manual runs do not compare coverage.

## Building Rialto using Yocto:
https://wiki.rdkcentral.com/display/ASP/Building+Rialto+using+Yocto

## Running Rialto:
https://wiki.rdkcentral.com/display/ASP/Running+YouTube+with+Rialto

## Main (Rialto) project webpage:
https://rdkcentral.github.io/rialto/
