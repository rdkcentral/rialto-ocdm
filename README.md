# rialto-ocdm

## Coding Guidelines:
https://wiki.rdkcentral.com/display/ASP/Rialto+Coding+Guidelines

## Building and Running Unit Tests:
Currently, Unit tests are not available for rialto-ocdm

## Building Rialto using Yocto:
https://wiki.rdkcentral.com/display/ASP/Building+Rialto+using+Yocto

## Running Rialto:
https://wiki.rdkcentral.com/display/ASP/Running+YouTube+with+Rialto

## Build tests (work in progress):
mkdir build && cd build
cmake -DCMAKE_BUILD_FLAG=UnitTests ..
make RialtoOcdmUnitTests -j16
RIALTO_CONSOLE_LOG=1 RIALTO_DEBUG=5 ./tests/ut/RialtoOcdmUnitTests
