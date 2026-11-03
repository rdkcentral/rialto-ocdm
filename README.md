# rialto-ocdm

## Project webpage:

https://rdkcentral.github.io/rialto-ocdm/

## Coding Guidelines:

https://wiki.rdkcentral.com/display/ASP/Rialto+Coding+Guidelines

## Commit message template:

https://wiki.rdkcentral.com/display/ASP/Commit+message+template

## Building and Running Unit Tests:

https://wiki.rdkcentral.com/display/ASP/Unit+Tests


The [unit-test](.github/workflows/build_ut.yml) and
[Valgrind](.github/workflows/valgrind_ut.yml) workflows use a matching Rialto PR
branch first, then a matching PR target branch. If neither lookup succeeds, they
use `RIALTO_FALLBACK_BRANCH`, set to Rialto `release/v0.15.2` for this 8.6 release.
Lookup errors also trigger fallback. Push and manual runs retain the event ref
name rather than applying the PR fallback.

Coverage comparison and comments run only for PRs targeting `master`. Release
PRs still generate and upload coverage, without a baseline comparison.

## Building Rialto using Yocto:

https://wiki.rdkcentral.com/display/ASP/Building+Rialto+using+Yocto

## Running Rialto:

https://wiki.rdkcentral.com/display/ASP/Running+YouTube+with+Rialto

## Main (Rialto) project webpage:

https://rdkcentral.github.io/rialto/
