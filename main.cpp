#include <curl/curl.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <thread>
#include <filesystem>
#include <algorithm>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

class APIMonitor {
private:
    struct MonitorResult {
        std::string url;
        long response_code;
        double response_time;
        std::string status;
        std::string timestamp;
        std::string error_message;
    };

    std::vector<std::string> urls;
    std::string log_file_path;
    int monitor_interval_seconds;

    // Callback function for curl to write response data
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
        ((std::string*)userp)->append((char*)contents, size * nmemb);
        return size * nmemb;
    }

    std::string getCurrentTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()) % 1000;

        std::stringstream ss;
        ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        ss << "." << std::setfill('0') << std::setw(3) << ms.count();
        return ss.str();
    }

    MonitorResult testURL(const std::string& url) {
        MonitorResult result;
        result.url = url;
        result.timestamp = getCurrentTimestamp();
        result.response_code = 0;
        result.response_time = 0.0;
        result.status = "FAILED";
        result.error_message = "";

        CURL* curl = curl_easy_init();
        if (!curl) {
            result.error_message = "Failed to initialize CURL";
            return result;
        }

        std::string response_string;

        // Set curl options
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);  // 30 second timeout
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);  // 10 second connection timeout
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);  // Follow redirects
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);  // Verify SSL certificates
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "API-Monitor/1.0");

        // Perform the request
        CURLcode res = curl_easy_perform(curl);

        if (res == CURLE_OK) {
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.response_code);
            curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &result.response_time);

            if (result.response_code >= 200 && result.response_code < 400) {
                result.status = "SUCCESS";
            } else {
                result.status = "FAILED";
                result.error_message = "HTTP " + std::to_string(result.response_code);
            }
        } else {
            result.error_message = curl_easy_strerror(res);
            result.status = "FAILED";
        }

        curl_easy_cleanup(curl);
        return result;
    }

    void logResult(const MonitorResult& result) {
        std::ofstream log_file(log_file_path, std::ios::app);
        if (!log_file.is_open()) {
            std::cerr << "Error: Could not open log file: " << log_file_path << std::endl;
            return;
        }

        // CSV format: timestamp,url,status,response_code,response_time_ms,error_message
        log_file << result.timestamp << ","
                 << result.url << ","
                 << result.status << ","
                 << result.response_code << ","
                 << std::fixed << std::setprecision(3) << (result.response_time * 1000) << ","
                 << result.error_message << std::endl;

        log_file.close();

        // Also print to console
        std::cout << "[" << result.timestamp << "] "
                  << result.url << " - " << result.status;
        if (result.status == "SUCCESS") {
            std::cout << " (HTTP " << result.response_code
                      << ", " << std::fixed << std::setprecision(3)
                      << (result.response_time * 1000) << "ms)";
        } else {
            std::cout << " (" << result.error_message << ")";
        }
        std::cout << std::endl;
    }

    void createLogFileHeader() {
        std::ifstream check_file(log_file_path);
        bool file_exists = check_file.good();
        check_file.close();

        if (!file_exists) {
            std::ofstream log_file(log_file_path);
            if (log_file.is_open()) {
                log_file << "timestamp,url,status,response_code,response_time_ms,error_message" << std::endl;
                log_file.close();
                std::cout << "Created log file: " << log_file_path << std::endl;
            }
        }
    }

public:
    APIMonitor(const std::vector<std::string>& url_list,
               const std::string& log_path = "api_monitor.csv",
               int interval = 60)
        : urls(url_list), log_file_path(log_path), monitor_interval_seconds(interval) {

        // Initialize libcurl
        curl_global_init(CURL_GLOBAL_DEFAULT);

        // Create log directory if it doesn't exist
        std::filesystem::path log_dir = std::filesystem::path(log_file_path).parent_path();
        if (!log_dir.empty()) {
            std::filesystem::create_directories(log_dir);
        }

        createLogFileHeader();
    }

    ~APIMonitor() {
        curl_global_cleanup();
    }

    void runSingleCheck() {
        std::cout << "\n=== Running API Monitor Check ===" << std::endl;
        std::cout << "Checking " << urls.size() << " URLs..." << std::endl;

        for (const std::string& url : urls) {
            MonitorResult result = testURL(url);
            logResult(result);
        }

        std::cout << "=== Check Complete ===" << std::endl;
    }

    void runContinuousMonitoring() {
        std::cout << "Starting continuous monitoring..." << std::endl;
        std::cout << "Monitoring " << urls.size() << " URLs every "
                  << monitor_interval_seconds << " seconds." << std::endl;
        std::cout << "Logging to: " << log_file_path << std::endl;
        std::cout << "Press Ctrl+C to stop." << std::endl;

        while (true) {
            runSingleCheck();

            std::cout << "Waiting " << monitor_interval_seconds
                      << " seconds until next check..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(monitor_interval_seconds));
        }
    }

    void setMonitorInterval(int seconds) {
        monitor_interval_seconds = seconds;
    }

    void addURL(const std::string& url) {
        urls.push_back(url);
    }

    void removeURL(const std::string& url) {
        urls.erase(std::remove(urls.begin(), urls.end(), url), urls.end());
    }

    void listURLs() {
        std::cout << "\nConfigured URLs:" << std::endl;
        for (size_t i = 0; i < urls.size(); ++i) {
            std::cout << (i + 1) << ". " << urls[i] << std::endl;
        }
        std::cout << std::endl;
    }
};

int main(int argc, char* argv[]) {
    // Default URLs to monitor
    std::vector<std::string> urls = {
        "https://httpbin.org/status/200",
        "https://jsonplaceholder.typicode.com/posts/1",
        "https://api.github.com",
        "https://httpstat.us/200"
    };

    // Check if URLs were provided as command line arguments
    if (argc > 1) {
        urls.clear();
        for (int i = 1; i < argc; ++i) {
            urls.push_back(argv[i]);
        }
    }

    try {
        // Create monitor with custom log path and interval
        APIMonitor monitor(urls, "logs/api_monitor.csv", 30);  // Check every 30 seconds

        monitor.listURLs();

        std::cout << "Choose monitoring mode:" << std::endl;
        std::cout << "1. Single check" << std::endl;
        std::cout << "2. Continuous monitoring" << std::endl;
        std::cout << "Enter choice (1 or 2): ";

        int choice;
        std::cin >> choice;

        if (choice == 1) {
            monitor.runSingleCheck();
        } else if (choice == 2) {
            monitor.runContinuousMonitoring();
        } else {
            std::cout << "Invalid choice. Running single check..." << std::endl;
            monitor.runSingleCheck();
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
