// tinyhttpd Copyright (C) 2024 kernaltrap8
// This program comes with ABSOLUTELY NO WARRANTY
// This is free software, and you are welcome to redistribute it
// under certain conditions

/*
  tinyhttpd.cpp
*/

#include "tinyhttpd.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <csignal>
#include <cstring>
#include <ctime>
#include <deque>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <mutex>
#include <pwd.h>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace tinyhttpd {
std::string basePath = ".";
volatile sig_atomic_t exitFlag = 0;
bool debugMode = false;
bool enableRateLimit = false;
long unsigned int rateLimit = 30;
const std::string RED = "\033[31m";
const std::string GREEN = "\033[32m";
const std::string RESET = "\033[0m";

// Define the blacklisted paths
std::unordered_set<std::string> blacklistedPaths = {};

// Struct to hold data for argument parsing
struct Argument {
  std::string flag;
  std::string value;
};

struct FileInfo {
  std::string name;
  std::string filePath;
  std::time_t mtime;
  long long size;
  bool isDirectory;
};

// Define a global map for tracking client request timestamps
std::unordered_map<std::string, std::deque<std::time_t>>
    clientRequestTimestamps;
std::mutex rateLimitMutex;

// Function to parse argument data from Argument struct
std::unordered_map<std::string, std::string> ParseArguments(int argc,
                                                            char *argv[]) {
  std::unordered_map<std::string, std::string> arguments;

  for (int i = 1; i < argc; ++i) {
    std::string arg = argv[i];

    if (arg.size() > 1 && arg[0] == '-') {
      // Remove leading dash
      arg.erase(0, 1);

      // Check if there's an associated value
      std::string value;
      if (i + 1 < argc && argv[i + 1][0] != '-') {
        value = argv[++i];
      }

      // Store flag and value pair
      arguments[arg] = value;
    }
  }

  return arguments;
}

void AddBlacklistedPaths(const std::string &paths) {
  std::istringstream stream(paths);
  std::string path;
  while (std::getline(stream, path, ',')) {
    blacklistedPaths.insert(path);
  }
}

void PrintCurrentOperation(const std::string operation) {
  std::cout << "[" << GREEN << "SERVER" << RESET << "] " << operation
            << std::endl;
}

void LogRequest(const std::string &ipAddress, const std::string &requestTime,
                const std::string &method, const std::string &requestPath,
                const std::string &httpVersion, int statusCode,
                const std::string &request) {
  std::cout << ipAddress << " - - [" << requestTime << "] \"" << method << " "
            << requestPath << " " << httpVersion << "\" " << statusCode
            << std::endl;
  if (debugMode) {
    std::cerr << "[" << RED << "DEBUG" << RESET << "] Request: " << request
              << std::endl;
  }
}

void LogResponse(const std::string &response) {
  if (debugMode) {
    std::cerr << "[" << RED << "DEBUG" << RESET << "] Response: " << response
              << std::endl;
  }
}

bool CheckRateLimit(const std::string &clientIp) {
  std::lock_guard<std::mutex> lock(rateLimitMutex);

  // Get current time
  std::time_t currentTime = std::time(nullptr);

  // Get the deque of timestamps for the client IP
  auto &timestamps = clientRequestTimestamps[clientIp];

  // Remove timestamps older than 1 second
  while (!timestamps.empty() && currentTime - timestamps.front() > 1) {
    timestamps.pop_front();
  }

  // Check if the number of requests exceeds the limit
  if (timestamps.size() >= rateLimit) {
    return false; // Rate limit exceeded
  }

  // Add the current timestamp
  timestamps.push_back(currentTime);
  return true; // Rate limit not exceeded
}

std::string UrlDecode(const std::string &str) {
  std::string result;
  char decodeBuf[3] = {0};
  for (size_t i = 0; i < str.length(); ++i) {
    if (str[i] == '%') {
      if (i + 2 < str.length()) {
        decodeBuf[0] = str[i + 1];
        decodeBuf[1] = str[i + 2];
        result += static_cast<char>(strtol(decodeBuf, nullptr, 16));
        i += 2;
      }
    } else if (str[i] == '+') {
      result += ' ';
    } else {
      result += str[i];
    }
  }
  return result;
}

bool compareByName(const FileInfo &a, const FileInfo &b) {
  return a.name < b.name;
}

bool compareByMtime(const FileInfo &a, const FileInfo &b) {
  return a.mtime > b.mtime; // Newest first
}

bool compareBySize(const FileInfo &a, const FileInfo &b) {
  return a.size > b.size; // Largest first
}

void ServeDirectoryListing(int ClientSocket, const std::string &directoryPath,
                           const std::string &requestPath, int portNumber) {
  std::string indexPath = directoryPath + "/index.html";
  std::ifstream indexFile(indexPath);

  if (!indexFile) {
    // If index.html does not exist, try index.htm
    indexPath = directoryPath + "/index.htm";
    indexFile.open(indexPath);
  }

  if (indexFile) {
    // If index.html exists, serve it
    std::stringstream response;
    response << indexFile.rdbuf(); // Read the content of index.html

    std::string responseStr = response.str();
    std::string responseHeader =
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " +
        std::to_string(responseStr.length()) + "\r\n\r\n";
    send(ClientSocket, responseHeader.c_str(), responseHeader.length(),
         MSG_NOSIGNAL);
    send(ClientSocket, responseStr.c_str(), responseStr.length(), MSG_NOSIGNAL);
    close(ClientSocket);

    LogResponse(responseStr);
    return;
  }

  std::stringstream response;
  response << "\r\n";
  response
      << "<html><head>"
         "<title>Directory Listing</title></head>"
         "<style>"
         "html, body { height: 100%; margin: 0; }"
         "body { display: flex; flex-direction: column; margin: 0; }"
         "main { flex: 1; overflow-y: auto; padding: 10px; position: relative; "
         "}"
         "ul { list-style-type: none; margin: 0; padding: 0; white-space: "
         "nowrap; }"
         "li { display: flex; align-items: center; padding-left: 20px; "
         "position: relative; }"
         "li.directory::before { content: '\\1F4C1'; margin-right: 10px; }"
         "li.file::before { content: '\\1F4C4'; margin-right: 10px; }"
         ".file-info { position: absolute; left: 500px; top: 0; "
         "background-color: #ffffff; z-index: 1; }"
         ".file-info span { display: inline-block; white-space: nowrap; }"
         "footer { background-color: #dddddd; padding: 7px; text-align: "
         "center; }"
         "a { color: #0000EE; text-decoration: underline; }"
         "</style>"
         "</head><body>\r\n"
         "<main>\r\n"
         "<h1 style=\"background-color: #dddddd; padding: 10px;\">Index of "
      << requestPath << "</h1>\r\n";
  response << "<ul>\r\n";
  // Add parent directory link
  if (requestPath != "/") {
    std::string parentPath = requestPath;
    if (parentPath.back() == '/') {
      parentPath.pop_back();
    }
    size_t pos = parentPath.find_last_of('/');
    if (pos != std::string::npos) {
      parentPath = parentPath.substr(0, pos);
    }
    if (parentPath.empty()) {
      parentPath = "/";
    }
    response << "<li class=\"directory\"><a href=\"" << parentPath
             << "\">..</a></li>";
  }

  // Read directory contents and collect entries
  std::vector<FileInfo> filesAndDirs;
  DIR *dir;
  struct dirent *ent;
  if ((dir = opendir(directoryPath.c_str())) != NULL) {
    while ((ent = readdir(dir)) != NULL) {
      std::string filename(ent->d_name);
      if (filename != "." && filename != "..") {
        std::string fullPath = directoryPath + "/" + filename;

        struct stat pathStat;
        if (stat(fullPath.c_str(), &pathStat) != 0) {
          response << "<p>Error reading file information.</p>\r\n";
          continue;
        }

        FileInfo fileInfo;
        fileInfo.name = filename;
        fileInfo.filePath =
            requestPath + (requestPath.back() == '/' ? "" : "/") + filename;
        fileInfo.mtime = pathStat.st_mtime;
        fileInfo.size = pathStat.st_size;
        fileInfo.isDirectory = S_ISDIR(pathStat.st_mode);

        filesAndDirs.push_back(fileInfo);
      }
    }
    closedir(dir);
  } else {
    response << "<p>Error reading directory.</p>\r\n";
  }

  // Sort entries by all criteria in a composite manner
  std::sort(filesAndDirs.begin(), filesAndDirs.end(),
            [](const FileInfo &a, const FileInfo &b) {
              // First, sort by directory status (directories before files)
              if (a.isDirectory != b.isDirectory) {
                return a.isDirectory;
              }
              // Next, sort by name
              if (a.name != b.name) {
                return a.name < b.name;
              }
              // Then, sort by modification time
              if (a.mtime != b.mtime) {
                return a.mtime > b.mtime; // Newest first
              }
              // Finally, sort by size
              return a.size > b.size; // Largest first
            });

  // Find the maximum width of file info
  std::size_t maxLength = 0;
  for (const auto &info : filesAndDirs) {
    std::string sizeStr;
    if (info.size > 1LL << 30) { // Greater than 1 GB
      sizeStr = std::to_string(info.size / (1LL << 30)) + " GB";
    } else if (info.size > 1LL << 20) { // Greater than 1 MB but less than 1 GB
      sizeStr = std::to_string(info.size / (1LL << 20)) + " MB";
    } else if (info.size > 1LL << 10) { // Greater than 1 KB but less than 1 MB
      sizeStr = std::to_string(info.size / (1LL << 10)) + " KB";
    } else {
      sizeStr = std::to_string(info.size) + " bytes";
    }

    char dateBuffer[20];
    char timeBuffer[20];
    std::tm *tm = std::localtime(&info.mtime);
    std::strftime(dateBuffer, sizeof(dateBuffer), "%Y-%m-%d", tm);
    std::strftime(timeBuffer, sizeof(timeBuffer), "%H:%M:%S", tm);

    std::string infoStr =
        std::string(dateBuffer) + " " + std::string(timeBuffer) + " " + sizeStr;
    if (infoStr.length() > maxLength) {
      maxLength = infoStr.length();
    }
  }

  // Append entries
  for (const auto &info : filesAndDirs) {
    std::string date;
    std::string time;
    std::tm *tm = std::localtime(&info.mtime);
    char dateBuffer[20];
    char timeBuffer[20];
    std::strftime(dateBuffer, sizeof(dateBuffer), "%Y-%m-%d", tm);
    std::strftime(timeBuffer, sizeof(timeBuffer), "%H:%M:%S", tm);

    date = dateBuffer;
    time = timeBuffer;

    if (info.isDirectory) {
      response << "<li class=\"directory\"><a href=\"" << info.filePath << "\">"
               << info.name
               << "</a><div class=\"file-info\"><span style=\"width: "
               << maxLength << "ch; display: inline-block;\">" << date << " "
               << time << "</span></div></li>\r\n";
    } else {
      std::string sizeStr;
      if (info.size > 1LL << 30) { // Greater than 1 GB
        sizeStr = std::to_string(info.size / (1LL << 30)) + " GB";
      } else if (info.size >
                 1LL << 20) { // Greater than 1 MB but less than 1 GB
        sizeStr = std::to_string(info.size / (1LL << 20)) + " MB";
      } else if (info.size >
                 1LL << 10) { // Greater than 1 KB but less than 1 MB
        sizeStr = std::to_string(info.size / (1LL << 10)) + " KB";
      } else {
        sizeStr = std::to_string(info.size) + " bytes";
      }

      response << "<li class=\"file\"><a href=\"" << info.filePath << "\">"
               << info.name
               << "</a><div class=\"file-info\"><span style=\"width: "
               << maxLength << "ch; display: inline-block;\">" << date << " "
               << time << " " << sizeStr << "</span></div></li>\r\n";
    }
  }

  response << "</ul>\r\n";
  response << "</main>\r\n";
  response << "<footer>tinyhttpd/" << VERSION << " on "
           << GetLinuxDistribution() << " Serving port " << portNumber
           << "</footer>\r\n";
  response << "</body></html>\r\n";

  // Send the response
  std::string responseStr = response.str();
  std::string responseHeader =
      "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: " +
      std::to_string(responseStr.length()) + "\r\n\r\n";
  send(ClientSocket, responseHeader.c_str(), responseHeader.length(),
       MSG_NOSIGNAL);
  send(ClientSocket, responseStr.c_str(), responseStr.length(), MSG_NOSIGNAL);
  close(ClientSocket);

  LogResponse(responseStr);
}

std::string GetLinuxDistribution() {
  std::ifstream file("/etc/os-release");
  std::string line;
  std::string distro;

  while (std::getline(file, line)) {
    if (line.find("PRETTY_NAME=") != std::string::npos) {
      // Extract everything after "PRETTY_NAME="
      distro = line.substr(line.find("=") + 1);
      // Remove quotes and any trailing newline character
      distro.erase(std::remove(distro.begin(), distro.end(), '\"'),
                   distro.end());
      break;
    }
  }

  return distro;
}

std::string GetMimeType(const std::string &filePath) {
  std::string extension = filePath.substr(filePath.find_last_of('.') + 1);
  std::unordered_map<std::string, std::string> mimeTypes = {
      {"html", "text/html"},        {"htm", "text/html"},
      {"css", "text/css"},          {"js", "application/javascript"},
      {"json", "application/json"}, {"txt", "text/plain"},
      {"md", "text/markdown"},      {"xml", "application/xml"},
      {"csv", "text/csv"},          {"svg", "image/svg+xml"},
      {"yml", "text/yml"},
  };

  if (mimeTypes.find(extension) != mimeTypes.end()) {
    return mimeTypes[extension];
  }

  return "application/octet-stream";
}

std::unordered_map<std::string, std::string>
ParseHeaders(std::istringstream &requestStream) {
  std::unordered_map<std::string, std::string> headers;
  std::string line;
  while (std::getline(requestStream, line) && line != "\r") {
    auto colonPos = line.find(':');
    if (colonPos != std::string::npos) {
      std::string headerName = line.substr(0, colonPos);
      std::string headerValue = line.substr(colonPos + 2); // Skip the ": " part
      headerValue.pop_back(); // Remove the '\r' character
      headers[headerName] = headerValue;
    }
  }
  return headers;
}

void HandleClientRequest(int ClientSocket, int portNumber) {
  char buffer[4096] = {0};
  int valread = read(ClientSocket, buffer, 4096);
  if (valread <= 0) {
    close(ClientSocket);
    return;
  }

  std::string request(buffer);
  std::istringstream requestStream(request);
  std::string method;
  std::string requestPath;
  std::string httpVersion;

  // Parse the request line
  requestStream >> method >> requestPath >> httpVersion;

  // URL-decode the request path
  requestPath = UrlDecode(requestPath);

  // Construct the absolute file path
  std::string filePath = basePath + requestPath;

  // Parse headers
  std::unordered_map<std::string, std::string> headers =
      ParseHeaders(requestStream);

  // Extract client IP from headers
  std::string clientIp = headers["X-Forwarded-For"];
  if (clientIp.empty()) {
    clientIp = headers["X-Real-IP"];
  }

  // If no IP header found, fall back to getpeername
  if (clientIp.empty()) {
    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);
    getpeername(ClientSocket, (struct sockaddr *)&addr, &addrLen);
    char clientIpBuffer[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(addr.sin_addr), clientIpBuffer, INET_ADDRSTRLEN);
    clientIp = clientIpBuffer;
  }

  // Get the current time
  std::time_t currentTime = std::time(nullptr);
  std::tm *timeInfo = std::localtime(&currentTime);
  char timeBuffer[80];
  std::strftime(timeBuffer, 80, "%d/%b/%Y:%H:%M:%S %z", timeInfo);

  // Check rate limit
  if (enableRateLimit == true) {
    if (!CheckRateLimit(clientIp)) {
      std::string rateLimitResponse =
          "HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/html\r\n\r\n"
          "<html><body><h1>429 Too Many Requests</h1><p>You have sent too many "
          "requests. Please try again later.</p></body></html>";
      send(ClientSocket, rateLimitResponse.c_str(), rateLimitResponse.length(),
           MSG_NOSIGNAL);
      LogRequest(clientIp, timeBuffer, method, requestPath, httpVersion, 429,
                 request);
      close(ClientSocket);
      return;
    }
  }

  // Check if the request path is any of these blacklisted paths
  if (blacklistedPaths.find(requestPath) != blacklistedPaths.end()) {
    std::string forbiddenResponse =
        "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n"
        "<html><body><h1>403 Forbidden</h1><p>Access denied.</p></body></html>";
    send(ClientSocket, forbiddenResponse.c_str(), forbiddenResponse.length(),
         MSG_NOSIGNAL);
    LogRequest(clientIp, timeBuffer, method, requestPath, httpVersion, 403,
               request);
    close(ClientSocket);
    return;
  }

  if (method == "GET") {
    struct stat pathStat;
    if (stat(filePath.c_str(), &pathStat) == 0) {
      if (S_ISDIR(pathStat.st_mode)) {
        ServeDirectoryListing(ClientSocket, filePath, requestPath, portNumber);
        LogRequest(clientIp, timeBuffer, method, requestPath, httpVersion, 200,
                   request);
      } else if (S_ISREG(pathStat.st_mode)) {
        // Serve the file
        std::ifstream file(filePath, std::ios::binary);
        if (file) {
          std::stringstream response;
          std::stringstream content;

          content << file.rdbuf();
          std::string contentStr = content.str();

          // Determine the content type
          std::string contentType = GetMimeType(filePath);

          response << httpVersion << " 200 OK\r\n";
          response << "Content-Type: " << contentType << "\r\n";
          response << "Content-Disposition: inline\r\n"; // Display in browser
          response << "Content-Length: " << contentStr.size() << "\r\n\r\n";
          response << contentStr;

          std::string responseStr = response.str();
          send(ClientSocket, responseStr.c_str(), responseStr.size(),
               MSG_NOSIGNAL);
          LogRequest(clientIp, timeBuffer, method, requestPath, httpVersion,
                     200, request);
          LogResponse(responseStr);
        } else {
          std::string notFoundResponse =
              "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
              "<html><body><h1>404 Not Found</h1><p>The requested resource was "
              "not found on this server.</p></body></html>";
          send(ClientSocket, notFoundResponse.c_str(),
               notFoundResponse.length(), MSG_NOSIGNAL);
          LogRequest(clientIp, timeBuffer, method, requestPath, httpVersion,
                     404, request);
        }
        file.close();
      }
    } else {
      std::string notFoundResponse =
          "HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n"
          "<html><body><h1>404 Not Found</h1><p>The requested resource was "
          "not found on this server.</p></body></html>";
      send(ClientSocket, notFoundResponse.c_str(), notFoundResponse.length(),
           MSG_NOSIGNAL);
      LogRequest(clientIp, timeBuffer, method, requestPath, httpVersion, 404,
                 request);
    }
  }

  close(ClientSocket);
}

int BindToClientSocket(int SocketToBind) {
  int ServerSocket = socket(AF_INET, SOCK_STREAM, 0);
  if (ServerSocket == 0) {
    std::cerr << "Failed to initialize socket. Exiting.\n";
    return 1;
  }

  // Set socket option to reuse address
  int opt = 1;
  if (setsockopt(ServerSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) <
      0) {
    std::cerr << "setsockopt(SO_REUSEADDR) failed.\n";
    return 1;
  }

  sockaddr_in SocketAddress;
  SocketAddress.sin_family = AF_INET;
  SocketAddress.sin_addr.s_addr = INADDR_ANY;
  SocketAddress.sin_port = htons(SocketToBind);

  if (bind(ServerSocket, (sockaddr *)&SocketAddress, sizeof(SocketAddress)) <
      0) {
    std::cerr << "Failed to bind to socket " << SocketToBind << ".\n";
    return 1;
  }

  if (listen(ServerSocket, 3) < 0) {
    std::cerr << "Listener failed.\n";
    return 1;
  }

  std::vector<std::thread> HttpdServerThread_t;

  while (!exitFlag) {
    int ClientSocket = accept(ServerSocket, nullptr, nullptr);
    if (ClientSocket < 0) {
      std::cerr << "Client socket accept failed.\n";
      continue; // Continue accepting other connections
    }

    HttpdServerThread_t.emplace_back([ClientSocket, SocketToBind]() {
      HandleClientRequest(ClientSocket, SocketToBind);
      close(ClientSocket); // Ensure socket is closed
    });

    // Join all threads to ensure they finish before the server shuts down
    for (auto it = HttpdServerThread_t.begin();
         it != HttpdServerThread_t.end();) {
      if (it->joinable()) {
        it->join();
        it = HttpdServerThread_t.erase(it); // Remove completed thread
      } else {
        ++it;
      }
    }
  }

  // Close server socket before exiting
  close(ServerSocket);

  return 0;
}

} // namespace tinyhttpd

// Signal handler function
void signalHandler(int signum) {
  std::cerr << signum;
  std::cout << "\n";
  std::string ExitingServerString = "Exiting.";
  tinyhttpd::PrintCurrentOperation(ExitingServerString);
  // Set exit flag to terminate server gracefully
  tinyhttpd::exitFlag = 1;
  exit(1);
}

int main(int argc, char *argv[]) {

  std::unordered_map<std::string, std::string> arguments =
      tinyhttpd::ParseArguments(argc, argv);
  if (arguments.count("h") > 0 || arguments.count("help") > 0) {
    std::cout << help;
    exit(0);
  }

  if (argc < 2) {
    std::cerr << "Please specify port to bind on.\n";
    exit(1);
  }

  if (arguments.count("v") > 0 || arguments.count("-version") > 0) {
    std::cout << "tinyhttpd v" << VERSION << std::endl;
    exit(0);
  }

  if (arguments.count("port") == 0) {
    std::cerr << "Please specify port to bind on using -port <port_number>\n";
    exit(1);
  }

  if (arguments.count("d") > 0) {
    tinyhttpd::debugMode = true;
  }

  if (arguments.count("-debug") > 0) {
    tinyhttpd::debugMode = true;
  }

  if (arguments.count("b") > 0) {
    tinyhttpd::AddBlacklistedPaths(arguments["b"]);
  }

  if (arguments.count("-blacklist") > 0) {
    tinyhttpd::AddBlacklistedPaths(arguments["-blacklist"]);
  }

  if (arguments.count("r") == 0 || arguments.count("-rate-limit") == 0) {
    tinyhttpd::enableRateLimit = true;
  }

  if (arguments.count("r") > 0) {
    tinyhttpd::enableRateLimit = true;
    unsigned long limit = std::stoul(arguments["r"].c_str());
    tinyhttpd::rateLimit = limit;
    std::cout << "Rate limit is: " << limit << std::endl;
  }

  if (arguments.count("-rate-limit") > 0) {
    tinyhttpd::enableRateLimit = true;
    unsigned long limit = std::stoul(arguments["-rate-limit"].c_str());
    tinyhttpd::rateLimit = limit;
  }

  if (arguments.count("path") > 0) {
    tinyhttpd::basePath = arguments["path"];
  }

  int portNumber = std::atoi(arguments["port"].c_str());

  // Register signal SIGINT and signal handler
  signal(SIGINT, signalHandler);

  // Ignore SIGPIPE and continue with execution

  std::string StartingServerString =
      "Starting tinyhttpd server on port " + std::to_string(portNumber);
  tinyhttpd::PrintCurrentOperation(StartingServerString);

  // Start the server
  return tinyhttpd::BindToClientSocket(portNumber);
}
