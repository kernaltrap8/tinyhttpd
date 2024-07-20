// tinyhttpd Copyright (C) 2024 kernaltrap8
// This program comes with ABSOLUTELY NO WARRANTY
// This is free software, and you are welcome to redistribute it
// under certain conditions

/*
  tinyhttpd.hpp
*/

#ifndef TINYHTTPD_HPP
#define TINYHTTPD_HPP

#include <string>
#include <unordered_map>
#include <vector>

#define VERSION "0.11.0d"

// Namespace for tinyhttpd functions and variables
namespace tinyhttpd {

// Function Declarations
std::unordered_map<std::string, std::string> ParseArguments(int argc,
                                                            char *argv[]);
void PrintCurrentOperation(const std::string operation);
void LogRequest(const std::string &ipAddress, const std::string &requestTime,
                const std::string &method, const std::string &requestPath,
                const std::string &httpVersion, int statusCode,
                const std::string &request);
void LogResponse(const std::string &response, const std::string &clientIp);
std::string UrlDecode(const std::string &str);
void ServeDirectoryListing(int ClientSocket, const std::string &directoryPath,
                           const std::string &requestPath, int portNumber);
std::string GetLinuxDistribution();
void HandleClientRequest(int ClientSocket, int portNumber);
int BindToClientSocket(int SocketToBind);

} // namespace tinyhttpd

// Signal handler function declaration
void signalHandler(int signum);

#endif // TINYHTTPD_HPP
