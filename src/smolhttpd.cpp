#include "smolhttpd.hpp"
#include <algorithm>
#include <arpa/inet.h>
#include <csignal>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace smolhttpd {

// Struct to hold data for argument parsing
struct Argument {
  std::string flag;
  std::string value;
};

// Function to parse argument data from Argument stuct
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

void PrintCurrentOperation(const std::string operation) {
  std::cout << "[SERVER] " << operation << std::endl;
}

void LogRequest(const std::string &ipAddress, const std::string &requestTime,
                const std::string &method, const std::string &requestPath,
                const std::string &httpVersion, int statusCode) {
  std::cout << ipAddress << " - - [" << requestTime << "] \"" << method << " "
            << requestPath << " HTTP/" << httpVersion << "\" " << statusCode
            << std::endl;
}

void ServeDirectoryListing(int ClientSocket, const std::string &directoryPath,
                           const std::string &requestPath, int portNumber) {
  std::stringstream response;
  response << "HTTP/1.1 200 OK\r\n";
  response << "Content-Type: text/html\r\n\r\n";
  response << "<html><head><title>Directory Listing</title></head><body "
              "style=\"background-color: #ffffff;\">\r\n";
  response
      << "<h1 style=\"background-color: #dddddd; padding: 10px;\">Index of "
      << requestPath << "</h1>\r\n";
  response << "<ul>\r\n";

  // Add parent directory link
  if (requestPath != "/") {
    response << "<li><a href=\"../\">Parent Directory</a></li>\r\n";
  }

  // Read directory contents
  DIR *dir;
  struct dirent *ent;
  if ((dir = opendir(directoryPath.c_str())) != NULL) {
    while ((ent = readdir(dir)) != NULL) {
      std::string filename(ent->d_name);
      if (filename != "." && filename != "..") {
        response << "<li><a href=\"" << filename << "\">" << filename
                 << "</a></li>\r\n";
      }
    }
    closedir(dir);
  } else {
    response << "<p>Error reading directory.</p>\r\n";
  }

  response << "</ul>\r\n";
  response << "<div style=\"background-color: #dddddd; padding: 10px; "
              "position: fixed; bottom: 0; width: 100%; text-align: center;\">"
              "smolhttpd/"
           << VERSION << " on " << GetLinuxDistribution() << " Serving port "
           << portNumber << "</div>\r\n";
  response << "</body></html>\r\n";

  send(ClientSocket, response.str().c_str(), response.str().length(), 0);
  close(ClientSocket);
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

void HandleClientRequest(int ClientSocket, int portNumber) {
  char buffer[4096] = {0};
  int valread = read(ClientSocket, buffer, 4096);
  if (valread <= 0) {
    close(ClientSocket);
    return;
  }

  // Extract IP and Port
  sockaddr_in clientAddr;
  socklen_t clientAddrLen = sizeof(clientAddr);
  getpeername(ClientSocket, (sockaddr *)&clientAddr, &clientAddrLen);
  char clientIP[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &clientAddr.sin_addr, clientIP, INET_ADDRSTRLEN);

  // Parse HTTP Request
  std::string request(buffer);
  size_t pos1 = request.find(" ");
  size_t pos2 = request.find(" ", pos1 + 1);
  size_t pos3 = request.find("\r\n");
  if (pos1 == std::string::npos || pos2 == std::string::npos ||
      pos3 == std::string::npos) {
    close(ClientSocket);
    return;
  }

  std::string method = request.substr(0, pos1);
  std::string requestPath = request.substr(pos1 + 1, pos2 - pos1 - 1);
  std::string httpVersion = request.substr(pos2 + 1, pos3 - pos2 - 1);

  // Generate request time
  time_t now = time(0);
  tm *gmtm = gmtime(&now);
  char requestTime[64];
  strftime(requestTime, sizeof(requestTime), "%d/%b/%Y:%H:%M:%S %z", gmtm);

  // Determine HTTP status code
  int statusCode = 200; // Default to 200 OK

  // Handle serving files
  std::string basePath = ".";
  std::string filePath = basePath + requestPath;
  if (requestPath == "/" || requestPath == "/index.html") {
    filePath = basePath + "/index.html";
  }

  std::ifstream fileStream(filePath, std::ios::in | std::ios::binary);
  if (!fileStream.is_open()) {
    statusCode = 404; // Not Found
    fileStream.close();

    // Check if directory and serve listing
    if (requestPath.back() != '/') {
      requestPath += '/';
    }

    std::string directoryPath = basePath + requestPath;
    ServeDirectoryListing(ClientSocket, directoryPath, requestPath, portNumber);
    return;
  }

  // Log the request
  LogRequest(clientIP, requestTime, method, requestPath, httpVersion,
             statusCode);

  // Prepare response based on status code and content of file
  std::stringstream response;
  response << "HTTP/1.1 ";
  switch (statusCode) {
  case 200:
    response << "200 OK\r\n";
    break;
  case 404:
    response << "404 Not Found\r\n";
    break;
  default:
    response << "500 Internal Server Error\r\n";
  }

  // Determine Content-Type
  std::string contentType;
  if (filePath.find(".html") != std::string::npos) {
    contentType = "text/html";
  } else if (filePath.find(".txt") != std::string::npos) {
    contentType = "text/plain";
  } else if (filePath.find(".jpg") != std::string::npos ||
             filePath.find(".jpeg") != std::string::npos) {
    contentType = "image/jpeg";
  } else if (filePath.find(".png") != std::string::npos) {
    contentType = "image/png";
  } else {
    contentType = "application/octet-stream"; // Default
  }

  // Read file content into response
  std::stringstream fileContent;
  fileContent << fileStream.rdbuf();
  fileStream.close();

  response << "Content-Type: " << contentType << "\r\n";
  response << "Content-Length: " << fileContent.str().length() << "\r\n";
  response << "\r\n";
  response << fileContent.str();

  // Send response
  send(ClientSocket, response.str().c_str(), response.str().length(), 0);
  close(ClientSocket);
}

int BindToClientSocket(int SocketToBind) {
  // Global variable for exit flag
  volatile sig_atomic_t exitFlag = 0;

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
      return 1;
    }
    HttpdServerThread_t.emplace_back(smolhttpd::HandleClientRequest,
                                     ClientSocket, SocketToBind);
  }

  // Join all threads before exiting
  for (auto &t : HttpdServerThread_t) {
    t.join();
  }

  // Close server socket before exiting
  close(ServerSocket);

  return 0;
}

} // namespace smolhttpd

// Global variable for exit flag
volatile sig_atomic_t exitFlag = 0;

// Signal handler function
void signalHandler(int signum) {
  std::cout << "\n";
  std::string ExitingServerString =
      "Exiting. (Signal: " + std::to_string(signum) + ")";
  smolhttpd::PrintCurrentOperation(ExitingServerString);
  // Set exit flag to terminate server gracefully
  exitFlag = 1;
  exit(1);
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    std::cerr << "Please specify port to bind on.\n";
    return 1;
  }

  std::unordered_map<std::string, std::string> arguments =
      smolhttpd::ParseArguments(argc, argv);

  if (arguments.count("v") > 0 || arguments.count("version") > 0) {
    std::cout << "smolhttpd v" << VERSION << std::endl;
    exit(0);
  }

  if (arguments.count("port") == 0) {
    std::cerr << "Please specify port to bind on using -port <port_number>\n";
    return 1;
  }

  int portNumber = std::atoi(arguments["port"].c_str());

  // Register signal SIGINT and signal handler
  signal(SIGINT, signalHandler);

  std::string StartingServerString =
      "Starting smolhttpd server on port " + std::to_string(portNumber);
  smolhttpd::PrintCurrentOperation(StartingServerString);

  // Start the server
  return smolhttpd::BindToClientSocket(portNumber);
}
