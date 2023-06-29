#ifndef LOGGER_H
#define LOGGER_H

#include <fstream>
#include <mutex>
#include <sstream>
#include <string>

enum Severity
{
    fatal = 0,
    error = 1,
    warn = 2,
    mil = 3,
    info = 4,
    debug = 5
};

class LogFile
{
public:
    static LogFile &instance();
    bool write(const std::string &line);
    bool isEnabled() const;

private:
    LogFile();
    ~LogFile();

private:
    std::fstream m_file;
    std::mutex m_mutex;
};

class Logger;
class Flusher
{
public:
    Flusher(std::stringstream &stream, const std::string &componentName, const Severity &severity);
    ~Flusher();

    template <typename T> Flusher &operator<<(const T &text)
    {
        m_stream << text;
        return *this;
    }

private:
    std::stringstream &m_stream;
    Severity m_severity;
};

class Logger
{
public:
    explicit Logger(const std::string &componentName);
    Flusher operator<<(const Severity &) const;

private:
    const std::string m_componentName;
    mutable std::stringstream m_stream;
};

#endif // LOGGER_H
