#ifndef LOG_H
#define LOG_H

#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>

class Logger {
private:
    static std::ofstream log_file;

public:
    static void init_log(const std::string& filename);
    static void close_log();

    template<typename... Args>
    static void log(const std::string& level, const Args&... args) {
        if (log_file.is_open()) {
            std::ostringstream oss;
            oss << get_timestamp() << " [" << level << "] ";
            (oss << ... << args);
            log_file << oss.str() << std::endl;
        }
    }

private:
    static std::string get_timestamp();
};

#define LOG_IMPL(level, ...) \
    do { \
        std::ostringstream log_stream; \
        log_stream << __VA_ARGS__; \
        Logger::log(level, log_stream.str()); \
    } while(0)

#ifdef NDEBUG
    // Release mode: only INFO, WARNING, and ERROR
    #define LOG_DEBUG(...) ((void)0)
    #define LOG_INFO(...) LOG_IMPL("INFO", __VA_ARGS__)
    #define LOG_WARNING(...) LOG_IMPL("WARNING", __VA_ARGS__)
    #define LOG_ERROR(...) LOG_IMPL("ERROR", __VA_ARGS__)
#else
    // Debug mode: all log levels
    #define LOG_DEBUG(...) LOG_IMPL("DEBUG", __VA_ARGS__)
    #define LOG_INFO(...) LOG_IMPL("INFO", __VA_ARGS__)
    #define LOG_WARNING(...) LOG_IMPL("WARNING", __VA_ARGS__)
    #define LOG_ERROR(...) LOG_IMPL("ERROR", __VA_ARGS__)
#endif

#endif // LOG_H
