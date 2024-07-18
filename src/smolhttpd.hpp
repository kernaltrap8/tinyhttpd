// smolhttpd Copyright (C) 2024 kernaltrap8
// This program comes with ABSOLUTELY NO WARRANTY
// This is free software, and you are welcome to redistribute it
// under certain conditions

/*
  smolhttpd.hpp
*/

#ifndef SMOLHTTPD_HPP
#define SMOLHTTPD_HPP

#include <string>

#define VERSION "9.8"

namespace smolhttpd {

// Function declarations

void PrintCurrentOperation(std::string Operation);
void LogRequest(const std::string &ipAddress, const std::string &requestTime,
                const std::string &method, const std::string &requestPath,
                const std::string &httpVersion, int statusCode);
void ServeDirectoryListing(int ClientSocket, const std::string &directoryPath,
                           const std::string &requestPath, int portNumber);
void HandleClientRequest(int ClientSocket, int portNumber);
int BindToClientSocket(int SocketToBind);
std::string GetLinuxDistribution();

} // namespace smolhttpd

#endif // SMOLHTTPD_HPP
