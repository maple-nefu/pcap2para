#include "packet_feature.h"

#include <iostream>
#include <sstream>

#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/HttpLayer.h>

#include "progressbar.hpp"

#include "extract.h"


int get_packet_count(const std::string &pcap_path) {
    pcpp::IFileReaderDevice *size_reader = pcpp::IFileReaderDevice::getReader(pcap_path);

    if (size_reader == nullptr) {
        std::cerr << "Cannot determine reader for file type" << '\n';
        return -1;
    }

    if (!size_reader->open()) {
        std::cerr << "Cannot open " + pcap_path + " for reading" << '\n';
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
    std::vector<boost::regex> pattern_regexes;
    std::stringstream         para_ss(parameters);
    if (parameters.find(',') != std::string::npos) {
        std::string single_parameter;
        // multiple parameters
        while (std::getline(para_ss, single_parameter, ',')) {
            pattern_regexes.emplace_back(single_parameter + "=([^&]+)");
        }
    } else {
        // single parameter
        pattern_regexes.emplace_back(parameters + "=([^&]+)");
    }

    return pattern_regexes;
}

int match_regex_from_reader(const bool debug, std::ofstream &fout, const std::string &pcap_path, const int packetCount, const std::vector<boost::regex> &pattern_regexes) {
    pcpp::RawPacket          raw_packet;
    pcpp::IFileReaderDevice *reader = pcpp::IFileReaderDevice::getReader(pcap_path);
    reader->open();

    int         idx  = 0;
    int         proc = 0;
    progressbar pb(100);
    pb.show_bar(debug);
    while (reader->getNextPacket(raw_packet)) {
        if (debug) {
            idx++;
            // update progress bar every 1% of the total num of packets have been processed,
            // 100 is ratio which must equal to value in progressbar variable definition above.
            if (idx % (packetCount / 100) == 0) {
                pb.update();
            }
        }

        pcpp::Packet parsed_packet(&raw_packet);

        if (!parsed_packet.isPacketOfType(pcpp::TCP)) {
            continue;
        }

        if (pcpp::TcpLayer *tcpLayer = parsed_packet.getLayerOfType<pcpp::TcpLayer>();
            tcpLayer->getDstPort() != 80) {
            continue;
        }

        if (!parsed_packet.isPacketOfType(pcpp::HTTPRequest)) {
            continue;
        }

        const pcpp::HttpRequestLayer *http_layer = parsed_packet.getLayerOfType<pcpp::HttpRequestLayer>();

        if (http_layer->getProtocol() != pcpp::HTTPRequest) {
            continue;
        }

        const auto   data_ptr = reinterpret_cast<std::string_view::const_pointer>(http_layer->getData());
        const size_t size     = http_layer->getDataLen();

        if (data_ptr == nullptr || size <= 0) {
            continue;
        }

        proc++;

        const std::string_view   payload(data_ptr, size);
        std::vector<std::string> para_list = extract_payload(payload, pattern_regexes);

        if (!para_list.empty()) {
            // rsa_list.at(0) is always rsa string which length greater than 16
            // 16 is not a magic number but a thumb rule because content in rsa is a DES output
            // if (para_list.at(0).length() > 16) {
            for (const auto &p : para_list) {
                fout << p;
                if (&p != &para_list.back()) {
                    fout << ',';
                }
            }
            fout << '\n';
            // }
        }
    }

    reader->close();
    delete reader;

    std::cout << '\n';

    return proc;
}