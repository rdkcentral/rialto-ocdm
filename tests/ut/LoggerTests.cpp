/*
 * If not stated otherwise in this file or this component's LICENSE file the
 * following copyright and licenses apply:
 *
 * Copyright 2023 Sky UK
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "Logger.h"
#include <fstream>
#include <gtest/gtest.h>
#include <sstream>

namespace
{
const char *kRialtoDebugEnvVarName{"RIALTO_DEBUG"};
const char *kRialtoConsoleLogEnvVarName{"RIALTO_CONSOLE_LOG"};
const char *kRialtoLogPathEnvVarName{"RIALTO_LOG_PATH"};
const char *kLogFilename{"test.log"};

std::vector<Severity> readLogFile()
{
    std::string fileName = std::string(kLogFilename) + std::string(".ocdm");
    std::fstream file{fileName, std::fstream::in};
    EXPECT_TRUE(file.is_open());
    std::vector<Severity> presentSeverities{};
    std::string currentLine;
    while (std::getline(file, currentLine))
    {
        if (currentLine.find("[ftl]") != std::string::npos)
        {
            presentSeverities.push_back(Severity::fatal);
        }
        else if (currentLine.find("[err]") != std::string::npos)
        {
            presentSeverities.push_back(Severity::error);
        }
        else if (currentLine.find("[wrn]") != std::string::npos)
        {
            presentSeverities.push_back(Severity::warn);
        }
        else if (currentLine.find("[mil]") != std::string::npos)
        {
            presentSeverities.push_back(Severity::mil);
        }
        else if (currentLine.find("[inf]") != std::string::npos)
        {
            presentSeverities.push_back(Severity::info);
        }
        else if (currentLine.find("[dbg]") != std::string::npos)
        {
            presentSeverities.push_back(Severity::debug);
        }
    }
    file.close();
    return presentSeverities;
}
} // namespace

class LoggerTests : public testing::Test
{
public:
    LoggerTests() = default;
    ~LoggerTests() override
    {
        // Restore default env var values
        setenv(kRialtoDebugEnvVarName, "5", 1);
        setenv(kRialtoConsoleLogEnvVarName, "1", 1);
        unsetenv(kRialtoLogPathEnvVarName);
    }

    void verifyLogFile(const Severity &severity)
    {
        auto presentSeverities{readLogFile()};
        for (const Severity &s : presentSeverities)
        {
            EXPECT_TRUE(s <= severity);
        }
    }
};

// Just for coverage, not able to check anything
TEST_F(LoggerTests, ShouldLogToJournald)
{
    setenv(kRialtoDebugEnvVarName, "5", 1);
    unsetenv(kRialtoConsoleLogEnvVarName);
    unsetenv(kRialtoLogPathEnvVarName);
    Logger log{"Test"};
    log << fatal << "fatal";
    log << error << "error";
    log << warn << "warn";
    log << mil << "mil";
    log << info << "info";
    log << debug << "debug";
    log << static_cast<Severity>(6) << "???";
}

TEST_F(LoggerTests, ShouldLogFatalLogOnly)
{
    setenv(kRialtoDebugEnvVarName, "0", 1);
    unsetenv(kRialtoConsoleLogEnvVarName);
    setenv(kRialtoLogPathEnvVarName, kLogFilename, 1);
    LogFile::instance().reset();
    Logger log{"Test"};
    log << fatal << "fatal";
    log << error << "error";
    log << warn << "warn";
    log << mil << "mil";
    log << info << "info";
    log << debug << "debug";
    unsetenv(kRialtoLogPathEnvVarName);
    LogFile::instance().reset();
    verifyLogFile(Severity::fatal);
}

TEST_F(LoggerTests, ShouldLogErrorLogOrBelow)
{
    setenv(kRialtoDebugEnvVarName, "1", 1);
    unsetenv(kRialtoConsoleLogEnvVarName);
    setenv(kRialtoLogPathEnvVarName, kLogFilename, 1);
    LogFile::instance().reset();
    Logger log{"Test"};
    log << fatal << "fatal";
    log << error << "error";
    log << warn << "warn";
    log << mil << "mil";
    log << info << "info";
    log << debug << "debug";
    unsetenv(kRialtoLogPathEnvVarName);
    LogFile::instance().reset();
    verifyLogFile(Severity::error);
}

TEST_F(LoggerTests, ShouldLogWarningLogOrBelow)
{
    setenv(kRialtoDebugEnvVarName, "2", 1);
    unsetenv(kRialtoConsoleLogEnvVarName);
    setenv(kRialtoLogPathEnvVarName, kLogFilename, 1);
    LogFile::instance().reset();
    Logger log{"Test"};
    log << fatal << "fatal";
    log << error << "error";
    log << warn << "warn";
    log << mil << "mil";
    log << info << "info";
    log << debug << "debug";
    unsetenv(kRialtoLogPathEnvVarName);
    LogFile::instance().reset();
    verifyLogFile(Severity::warn);
}

TEST_F(LoggerTests, ShouldLogMilestoneLogOrBelow)
{
    setenv(kRialtoDebugEnvVarName, "3", 1);
    unsetenv(kRialtoConsoleLogEnvVarName);
    setenv(kRialtoLogPathEnvVarName, kLogFilename, 1);
    LogFile::instance().reset();
    Logger log{"Test"};
    log << fatal << "fatal";
    log << error << "error";
    log << warn << "warn";
    log << mil << "mil";
    log << info << "info";
    log << debug << "debug";
    unsetenv(kRialtoLogPathEnvVarName);
    LogFile::instance().reset();
    verifyLogFile(Severity::mil);
}

TEST_F(LoggerTests, ShouldLogInfoLogOrBelow)
{
    setenv(kRialtoDebugEnvVarName, "4", 1);
    unsetenv(kRialtoConsoleLogEnvVarName);
    setenv(kRialtoLogPathEnvVarName, kLogFilename, 1);
    LogFile::instance().reset();
    Logger log{"Test"};
    log << fatal << "fatal";
    log << error << "error";
    log << warn << "warn";
    log << mil << "mil";
    log << info << "info";
    log << debug << "debug";
    unsetenv(kRialtoLogPathEnvVarName);
    LogFile::instance().reset();
    verifyLogFile(Severity::info);
}

TEST_F(LoggerTests, ShouldLogAllLogs)
{
    setenv(kRialtoDebugEnvVarName, "5", 1);
    unsetenv(kRialtoConsoleLogEnvVarName);
    setenv(kRialtoLogPathEnvVarName, kLogFilename, 1);
    LogFile::instance().reset();
    Logger log{"Test"};
    log << fatal << "fatal";
    log << error << "error";
    log << warn << "warn";
    log << mil << "mil";
    log << info << "info";
    log << debug << "debug";
    unsetenv(kRialtoLogPathEnvVarName);
    LogFile::instance().reset();
    verifyLogFile(Severity::debug);
}

TEST_F(LoggerTests, ShouldLogDefaultLogOrBelowWhenEnvVarIsUnset)
{
    unsetenv(kRialtoDebugEnvVarName);
    unsetenv(kRialtoConsoleLogEnvVarName);
    setenv(kRialtoLogPathEnvVarName, kLogFilename, 1);
    LogFile::instance().reset();
    Logger log{"Test"};
    log << fatal << "fatal";
    log << error << "error";
    log << warn << "warn";
    log << mil << "mil";
    log << info << "info";
    log << debug << "debug";
    unsetenv(kRialtoLogPathEnvVarName);
    LogFile::instance().reset();
    verifyLogFile(Severity::warn);
}

// Just for coverage, not able to check anything
TEST_F(LoggerTests, ShouldLogAllSeveritiesToConsole)
{
    setenv(kRialtoDebugEnvVarName, "5", 1);
    setenv(kRialtoConsoleLogEnvVarName, "1", 1);
    unsetenv(kRialtoLogPathEnvVarName);
    Logger log{"Test"};
    log << fatal << "fatal";
    log << error << "error";
    log << warn << "warn";
    log << mil << "mil";
    log << info << "info";
    log << debug << "debug";
    log << static_cast<Severity>(6) << "???";
}
