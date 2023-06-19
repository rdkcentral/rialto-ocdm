#ifndef LOGGER_H
#define LOGGER_H

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

class Logger;
class Flusher
{
public:
    Flusher(std::stringstream &stream, const std::string &componentName, const Severity &severity);
    ~Flusher();

    template <typename T> Flusher &operator<<(const T &text)
    {
        mStream << text;
        return *this;
    }

private:
    std::stringstream &mStream;
    Severity mSeverity;
};

class Logger
{
public:
    explicit Logger(const std::string &componentName);
    Flusher operator<<(const Severity &) const;

private:
    const std::string mComponentName;
    mutable std::stringstream mStream;
};

#endif // LOGGER_H
