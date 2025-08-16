#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <curl/curl.h>
#include <iomanip>
#include <sstream>
#include "argparse/argparse.hpp"

struct ApiResponse {
    std::string url;
    int response_code;
    double response_time;
    std::string timestamp;
    bool success;
    std::string error_msg;
};

size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

std::string getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::ostringstream oss;
    oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

std::vector<std::string> loadUrlsFromFile(const std::string& filename) {
    std::vector<std::string> urls;
    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file " << filename << '\n';
        return urls;
    }

    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (!line.empty()) {
            urls.push_back(line);
        }
    }

    file.close();
    std::cout << "Loaded " << urls.size() << " URLs from " << filename << '\n';
    return urls;
}

ApiResponse testUrl(const std::string& url) {
    ApiResponse response;
    response.url = url;
    response.timestamp = getCurrentTimestamp();
    response.success = false;
    response.response_code = 0;
    response.response_time = 0.0;
    response.error_msg = "";

    CURL* curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (curl) {
        auto start = std::chrono::high_resolution_clock::now();

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

        res = curl_easy_perform(curl);

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        response.response_time = duration.count();

        if (res != CURLE_OK) {
            response.error_msg = curl_easy_strerror(res);
        } else {
            response.success = true;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response.response_code);
        }

        curl_easy_cleanup(curl);
    } else {
        response.error_msg = "Failed to initialize curl";
    }

    return response;
}

void logResponse(const ApiResponse& response, const std::string& logFile) {
    std::ofstream log(logFile, std::ios::app);
    if (!log.is_open()) {
        std::cerr << "Error: Cannot open log file " << logFile << '\n';
        return;
    }

    log << response.timestamp << " | "
        << response.url << " | "
        << "Status: " << response.response_code << " | "
        << "Time: " << response.response_time << "ms | "
        << "Success: " << (response.success ? "YES" : "NO");

    if (!response.error_msg.empty()) {
        log << " | Error: " << response.error_msg;
    }

    log << '\n';
    log.close();
}

void printResponse(const ApiResponse& response) {
    std::cout << "[" << response.timestamp << "] " << response.url << " -> ";
    if (response.success) {
        std::cout << "HTTP " << response.response_code
                  << " (" << response.response_time << "ms)";
    } else {
        std::cout << "FAILED (" << response.error_msg << ")";
    }
    std::cout << '\n';
}

void runBurstMode(const std::vector<std::string>& urls, const std::string& logFile) {
    std::cout << "\n=== BURST MODE ===\n";
    std::cout << "Testing " << urls.size() << " URLs.\n";

    for (const auto& url : urls) {
        ApiResponse response = testUrl(url);
        printResponse(response);
        logResponse(response, logFile);
    }

    std::cout << "\nBurst test completed. Results logged to: " << logFile << '\n';
}

void runContinuousMode(const std::vector<std::string>& urls, const std::string& logFile, int interval = 60) {
    std::cout << "\n=== CONTINUOUS MODE ===\n";
    std::cout << "Monitoring " << urls.size() << " URLs every " << interval << " seconds.\n";
    std::cout << "Press Ctrl+C to stop monitoring\n\n";

    int cycle = 1;
    while (true) {
        std::cout << "--- Cycle " << cycle << " ---\n";

        for (const auto& url : urls) {
            ApiResponse response = testUrl(url);
            printResponse(response);
            logResponse(response, logFile);
        }

        std::cout << "Waiting " << interval << " seconds until next cycle.\n\n";
        std::this_thread::sleep_for(std::chrono::seconds(interval));
        cycle++;
    }
}

int main(int argc, char* argv[]) {
    argparse::ArgumentParser program("api-monitor", "1.0");

    program.add_argument("mode")
        .help("Monitoring mode: 'burst' for one-time test, 'continuous' for repeated monitoring")
        .action([](const std::string& value) {
            if (value != "burst" && value != "continuous") {
                throw std::runtime_error("Mode must be either 'burst' or 'continuous'");
            }
            return value;
        });

    program.add_argument("-f", "--file")
        .required()
        .help("Path to file containing URLs (one per line)");

    program.add_argument("-l", "--log")
        .required()
        .help("Path to log file");

    program.add_argument("-i", "--interval")
        .default_value(60)
        .scan<'i', int>()
        .help("Interval in seconds for continuous mode (default: 60)");

    try {
        program.parse_args(argc, argv);
    } catch (const std::exception& err) {
        std::cerr << "Error: " << err.what() << '\n';
        std::cerr << program;
        return 1;
    }
\
    curl_global_init(CURL_GLOBAL_DEFAULT);

    std::string mode = program.get<std::string>("mode");
    std::string urlFile = program.get<std::string>("--file");
    std::string logFile = program.get<std::string>("--log");
    int interval = program.get<int>("--interval");

    std::vector<std::string> urls = loadUrlsFromFile(urlFile);
    if (urls.empty()) {
        std::cerr << "Error: No URLs loaded from file\n";
        curl_global_cleanup();
        return 1;
    }

    std::ofstream log(logFile, std::ios::app);
    if (log.tellp() == 0) {
        log << "=== API Monitor Log Started at " << getCurrentTimestamp() << " ===" << '\n';
    }
    log.close();

    std::cout << "API Monitor started" << '\n';
    std::cout << "Mode: " << mode << '\n';
    std::cout << "URLs file: " << urlFile << '\n';
    std::cout << "Log file: " << logFile << '\n';

    if (mode == "burst") {
        runBurstMode(urls, logFile);
    } else if (mode == "continuous") {
        runContinuousMode(urls, logFile, interval);
    }

    curl_global_cleanup();

    return 0;
}
