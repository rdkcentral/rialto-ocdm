#!/usr/bin/env python3

#
# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2023 Sky UK
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import re
import sys

def main():
    if len(sys.argv) < 3:
        write_output("Can't compare coverage stats - Wrong number of script arguments")
        sys.exit("Wrong number of script arguments")
    try:
        master_stats = parse_statistics(sys.argv[1])
        current_stats = parse_statistics(sys.argv[2])
    except (OSError, ValueError) as error:
        message = f"Can't compare coverage stats - {error}"
        write_output(message)
        sys.exit(message)
    comparison_output = compare_coverage(master_stats, current_stats)
    write_output(comparison_output)

    # If line coverage, funtion coverage individually or both decrease, it should exit
    if current_stats[0] < master_stats[0] and current_stats[1] < master_stats[1]:
        sys.exit("Line coverage and function coverage have both decreased. Exiting...")
    elif current_stats[0] < master_stats[0]:
        sys.exit("Line coverage has decreased. Exiting...")
    elif current_stats[1] < master_stats[1]:
        sys.exit("Function coverage has decreased. Exiting...")

def parse_statistics(file_path):
    with open(file_path, "r") as file:
        contents = file.read()
    statistics = []
    for metric in ("lines", "functions"):
        match = re.search(r"^\s*" + metric + r"\.+:\s*(\d+(?:\.\d+)?)%", contents, re.MULTILINE)
        if match is None or not 0 <= float(match.group(1)) <= 100:
            raise ValueError(f"Missing or invalid {metric} coverage in {file_path}")
        statistics.append(float(match.group(1)))
    return tuple(statistics)

def compare_coverage(master_stats, current_stats):
    output_text = "Coverage statistics of your commit:\n"
    if current_stats[0] < master_stats[0]:
        output_text += "WARNING: Lines coverage decreased from: " + str(master_stats[0]) + "% to "
        output_text += str(current_stats[0]) + "%\n"

    elif current_stats[0] == master_stats[0]:
        output_text += "Lines coverage stays unchanged and is: " + str(current_stats[0]) + "%\n"
    else:
        output_text += "Congratulations, your commit improved lines coverage from: " + str(master_stats[0])
        output_text += "% to " + str(current_stats[0]) + "%\n"

    if current_stats[1] < master_stats[1]:
        output_text += "WARNING: Functions coverage decreased from: " + str(master_stats[1]) + "% to "
        output_text += str(current_stats[1]) + "%\n"
    elif current_stats[1] == master_stats[1]:
        output_text += "Functions coverage stays unchanged and is: " + str(current_stats[1]) + "%\n"
    else:
        output_text += "Congratulations, your commit improved functions coverage from: " + str(master_stats[1])
        output_text += "% to " + str(current_stats[1]) + "%\n"
    return output_text

def write_output(output_text):
    output_file = open("comparison_output.txt", "w")
    output_file.write(output_text)
    output_file.close()

if __name__ == "__main__":
    main()
