#pragma once

#ifndef EXTRACT_H
#define EXTRACT_H

#include <vector>

#include <boost/regex.hpp>

std::vector<std::string> extract_payload(const std::string_view &payload, const std::vector<boost::regex> &regexes);

#endif // !EXTRACT_H