#include "packet_feature.h"

#include <iostream>
#include <sstream>
#include <fstream>
#include <format>

#include <tracy/Tracy.hpp>

#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/HttpLayer.h>

#include "progressbar.hpp"

#include "extract.h"


int get_packet_count(const std::string &pcap_path) {
    ZoneScoped;

    pcpp::IFileReaderDevice *size_reader = pcpp::IFileReaderDevice::getReader(pcap_path);

    if (size_reader == nullptr) {
        std::cerr << "Cannot determine reader for file type" << '\n';
        return -1;
    }

    if (!size_reader->open()) {
        std::cerr << std::format("Cannot open {} for reading\n", pcap_path);
        return -1;
    }

    int             packet_count = 0;
    pcpp::RawPacket tmp_packet;
    while (size_reader->getNextPacket(tmp_packet)) {
        packet_count++;
    }

    size_reader->close();
    delete size_reader;

    return packet_count;
}

std::vector<boost::regex> get_regexes(const std::string &parameters) {
    ZoneScoped;

    std::vector<boost::regex> pattern_regexes;
    std::stringstream         para_ss(parameters);
    if (parameters.find(',') != std::string::npos) { // check if multiple parameters
        std::string single_parameter;
        while (std::getline(para_ss, single_parameter, ',')) {
            pattern_regexes.emplace_back(single_parameter + "=([^&]+)");
        }
    } else {
        pattern_regexes.emplace_back(parameters + "=([^&]+)");
    }

    return pattern_regexes;
}

int match_regex_from_reader(const bool debug, std::ofstream &fout, const std::string &pcap_path, const int packetCount, const std::vector<boost::regex> &pattern_regexes) {
    ZoneScoped;

    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(pcap_path);
    reader->open();

    int         idx  = 0;
    int         proc = 0;
    progressbar pb(100);
    pb.show_bar(debug);

    pcpp::RawPacket raw_packet;
    while (reader->getNextPacket(raw_packet)) {
        if (debug) {
            // update progress bar every 1% of the total num of packets have been processed,
            // 100 is ratio which must equal to value in progressbar variable definition above.
            if (++idx % (packetCount / 100) == 0) {
                pb.update();
            }
        }

        pcpp::Packet parsed_packet(&raw_packet);

        if (!parsed_packet.isPacketOfType(pcpp::TCP)) {
            continue;
        }

        if (const pcpp::TcpLayer *tcp_layer = parsed_packet.getLayerOfType<pcpp::TcpLayer>();
            tcp_layer->getDstPort() != 80) {
            continue;
        }

        if (!parsed_packet.isPacketOfType(pcpp::HTTPRequest)) {
            continue;
        }

        const pcpp::HttpRequestLayer *http_layer = parsed_packet.getLayerOfType<pcpp::HttpRequestLayer>();

        if (http_layer->getProtocol() != pcpp::HTTPRequest) {
            continue;
        }

        const auto   payload_ptr = reinterpret_cast<std::string_view::const_pointer>(http_layer->getLayerPayload());
        const size_t size        = http_layer->getLayerPayloadSize();

        if (payload_ptr == nullptr || size <= 0) {
            continue;
        }

        proc++;

        const std::string_view   payload(payload_ptr, size);
        std::vector<std::string> para_list = extract_payload(payload, pattern_regexes);

        if (!para_list.empty()) {
            for (const auto &p : para_list) {
                fout << p;
                if (&p != &para_list.back()) {
                    fout << ',';
                }
            }
            fout << '\n';
        }
    }

    if (debug) {
        std::cout << '\n';
    }

    reader->close();
    delete reader;

    return proc;
}