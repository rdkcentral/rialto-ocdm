#include "Logger.h"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <syslog.h>
#include <unistd.h>

namespace
{
Severity getLogLevel()
{
    const char *debugVar = getenv("RIALTO_DEBUG");
    if (debugVar)
    {
        std::string varStr{debugVar};
        if ("0" == varStr)
            return Severity::fatal;
        if ("1" == varStr)
            return Severity::error;
        if ("2" == varStr)
            return Severity::warn;
        if ("3" == varStr)
            return Severity::mil;
        if ("4" == varStr)
            return Severity::info;
        if ("5" == varStr)
            return Severity::debug;
    }
    return Severity::warn;
}

bool isConsoleLogEnabled()
{
    const char *debugVar = getenv("RIALTO_CONSOLE_LOG");
    if (debugVar)
    {
        return std::string(debugVar) == "1";
    }
    return false;
}

std::string toString(const Severity &severity)
{
    if (Severity::fatal == severity)
        return "ftl";
    if (Severity::error == severity)
        return "err";
    if (Severity::warn == severity)
        return "wrn";
    if (Severity::mil == severity)
        return "mil";
    if (Severity::info == severity)
        return "inf";
    if (Severity::debug == severity)
        return "dbg";
    return "???";
}

int convertSeverity(const Severity &severity)
{
    switch (severity)
    {
    case Severity::fatal:
        return LOG_CRIT;
    case Severity::error:
        return LOG_ERR;
    case Severity::warn:
        return LOG_WARNING;
    case Severity::mil:
        return LOG_NOTICE;
    case Severity::info:
        return LOG_INFO;
    case Severity::debug:
        return LOG_DEBUG;
    default:
        break;
    }
    return LOG_DEBUG;
}
} // namespace

Flusher::Flusher(std::stringstream &stream, const std::string &componentName, const Severity &severity)
    : m_stream{stream}, m_severity{severity}
{
    if (isConsoleLogEnabled())
    {
        const std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
        const std::time_t t_c = std::chrono::system_clock::to_time_t(now);
        m_stream << std::put_time(std::localtime(&t_c), "[%F %T]");
    }
    m_stream << "[" << componentName << "][" << toString(severity) << "]: ";
}

Flusher::~Flusher()
{
    if (getLogLevel() >= m_severity)
    {
        if (isConsoleLogEnabled())
        {
            std::cout << m_stream.str() << std::endl;
        }
        else
        {
            syslog(convertSeverity(m_severity), "%s", m_stream.str().c_str());
        }
    }
    m_stream.str("");
}

Logger::Logger(const std::string &componentName) : m_componentName{componentName} {}

Flusher Logger::operator<<(const Severity &severity) const
{
    return Flusher(m_stream, m_componentName, severity);
}
