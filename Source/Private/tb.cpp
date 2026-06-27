#include <ap_int.h>
#include <ap_axi_sdata.h>
#include <hls_stream.h>

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>

#include "Data_SHA256.h"

typedef ap_axiu<32, 0, 0, 0> stream_t;

void hmac_sha256_top(hls::stream<stream_t>& in_stream,
                     hls::stream<stream_t>& out_stream,
                     ap_uint<256> key,
                     ap_uint<32> msg_len);

static ap_uint<256> pack_key_msb_first(const uint8_t key_bytes[SHA256_DIGEST_SIZE])
{
    ap_uint<256> key = 0;

    for (int i = 0; i < SHA256_DIGEST_SIZE; ++i) {
        key.range(255 - (i * 8), 248 - (i * 8)) = key_bytes[i];
    }

    return key;
}

static void print_bytes(const char* label, const uint8_t* data, int len)
{
    std::cout << label;
    for (int i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(data[i]);
    }
    std::cout << std::dec << std::setfill(' ') << std::endl;
}

static void push_message_axis(hls::stream<stream_t>& in_stream,
                              const uint8_t* msg,
                              unsigned int msg_len)
{
    const unsigned int word_count = (msg_len + 3U) / 4U;

    for (unsigned int word_idx = 0; word_idx < word_count; ++word_idx) {
        stream_t pkt;
        ap_uint<32> word = 0;
        ap_uint<4> keep = 0;

        for (unsigned int byte_idx = 0; byte_idx < 4U; ++byte_idx) {
            const unsigned int msg_idx = (word_idx * 4U) + byte_idx;

            if (msg_idx < msg_len) {
                const uint8_t byte = msg[msg_idx];

                // The DUT consumes TDATA[31:24] first, then [23:16], [15:8], [7:0].
                word.range(31 - (byte_idx * 8), 24 - (byte_idx * 8)) = byte;

                // Keep follows AXI byte-lane convention: bit 3 maps to TDATA[31:24].
                keep[3 - byte_idx] = 1;
            }
        }

        pkt.data = word;
        pkt.keep = keep;
        pkt.strb = keep;
        pkt.last = (word_idx == (word_count - 1U)) ? 1 : 0;
        in_stream.write(pkt);

        std::cout << "Input word[" << word_idx << "] = 0x"
                  << std::hex << std::setw(8) << std::setfill('0')
                  << word.to_uint()
                  << " keep=0x" << keep.to_uint()
                  << " last=" << pkt.last.to_uint()
                  << std::dec << std::setfill(' ') << std::endl;
    }
}

static bool pop_digest_axis(hls::stream<stream_t>& out_stream,
                            uint8_t actual[SHA256_DIGEST_SIZE])
{
    bool last_seen_correctly = false;

    for (int word_idx = 0; word_idx < 8; ++word_idx) {
        if (out_stream.empty()) {
            std::cout << "ERROR: Output stream underrun at word " << word_idx << std::endl;
            return false;
        }

        stream_t pkt = out_stream.read();
        ap_uint<32> word = pkt.data;

        actual[(word_idx * 4) + 0] = static_cast<uint8_t>(word.range(31, 24));
        actual[(word_idx * 4) + 1] = static_cast<uint8_t>(word.range(23, 16));
        actual[(word_idx * 4) + 2] = static_cast<uint8_t>(word.range(15, 8));
        actual[(word_idx * 4) + 3] = static_cast<uint8_t>(word.range(7, 0));

        const bool expected_last = (word_idx == 7);
        const bool actual_last = (pkt.last != 0);

        std::cout << "Output word[" << word_idx << "] = 0x"
                  << std::hex << std::setw(8) << std::setfill('0')
                  << word.to_uint()
                  << " last=" << actual_last
                  << std::dec << std::setfill(' ') << std::endl;

        if (actual_last != expected_last) {
            std::cout << "ERROR: TLAST mismatch at output word " << word_idx
                      << ", expected " << expected_last
                      << ", got " << actual_last << std::endl;
            return false;
        }

        if (expected_last && actual_last) {
            last_seen_correctly = true;
        }
    }

    if (!out_stream.empty()) {
        std::cout << "ERROR: Output stream contains extra data after digest." << std::endl;
        return false;
    }

    return last_seen_correctly;
}

int main()
{
    const char* message_text = "hello world";
    const uint8_t* message = reinterpret_cast<const uint8_t*>(message_text);
    const unsigned int message_len = static_cast<unsigned int>(std::strlen(message_text));

    const uint8_t key_bytes[SHA256_DIGEST_SIZE] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };

    const uint8_t expected[SHA256_DIGEST_SIZE] = {
        0x41, 0x1b, 0x9a, 0x51, 0xe8, 0x56, 0x5e, 0x1f,
        0xc7, 0x96, 0x43, 0xb2, 0xa6, 0xc4, 0x67, 0x2f,
        0x4a, 0x3c, 0x3e, 0x57, 0x3c, 0x33, 0xd0, 0x99,
        0x5a, 0x08, 0x74, 0x8c, 0xb6, 0x12, 0x8e, 0x8e
    };

    hls::stream<stream_t> in_stream("in_stream");
    hls::stream<stream_t> out_stream("out_stream");
    uint8_t actual[SHA256_DIGEST_SIZE] = {0};

    std::cout << "=== HMAC-SHA256 HLS C-Simulation Testbench ===" << std::endl;
    std::cout << "Message text : " << message_text << std::endl;
    std::cout << "Message length: " << message_len << " bytes" << std::endl;
    print_bytes("Key          : ", key_bytes, SHA256_DIGEST_SIZE);
    print_bytes("Expected HMAC: ", expected, SHA256_DIGEST_SIZE);

    push_message_axis(in_stream, message, message_len);

    hmac_sha256_top(in_stream,
                    out_stream,
                    pack_key_msb_first(key_bytes),
                    static_cast<ap_uint<32> >(message_len));

    const bool axis_ok = pop_digest_axis(out_stream, actual);
    print_bytes("Actual HMAC  : ", actual, SHA256_DIGEST_SIZE);

    bool digest_ok = true;
    for (int i = 0; i < SHA256_DIGEST_SIZE; ++i) {
        if (actual[i] != expected[i]) {
            std::cout << "Mismatch at digest byte " << i
                      << ": expected 0x" << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<unsigned int>(expected[i])
                      << ", got 0x" << std::setw(2)
                      << static_cast<unsigned int>(actual[i])
                      << std::dec << std::setfill(' ') << std::endl;
            digest_ok = false;
        }
    }

    if (axis_ok && digest_ok) {
        std::cout << "TEST PASS" << std::endl;
        return 0;
    }

    std::cout << "TEST FAIL" << std::endl;
    return 1;
}