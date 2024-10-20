#include "log.h"

std::ofstream Logger::log_file;

void Logger::init_log(const std::string& filename) {
    log_file.open(filename, std::ios::out | std::ios::app);
}

void Logger::close_log() {
    if (log_file.is_open()) {
        log_file.close();
    }
}

std::string Logger::get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto now_c = std::chrono::system_clock::to_time_t(now);
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S")
        << '.' << std::setfill('0') << std::setw(3) << now_ms.count();
    return oss.str();
}
