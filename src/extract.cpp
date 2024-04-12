#include "extract.h"

#include <tracy/Tracy.hpp>


std::vector<std::string> extract_payload(const std::string_view &payload, const std::vector<boost::regex> &regexes) {
    ZoneScoped;

    std::vector<std::string> extracted;
    extracted.reserve(regexes.size());
    for (const auto &pattern : regexes) {
        //boost::smatch results;
        if (boost::match_results<std::string_view::const_iterator> results;
            regex_search(payload.begin(), payload.end(), results, pattern)) {
            if (results.size() > 1) {
                auto result = results[1].str();
                extracted.emplace_back(result);
            }
        }
    }
    return extracted;
}