#include "Data_SHA256.h"
#include <ap_int.h>
#include <hls_stream.h>
#include <ap_axi_sdata.h>

typedef ap_axiu<32, 0, 0, 0> stream_t;

void hmac_sha256_top(hls::stream<stream_t>& in_stream,
                     hls::stream<stream_t>& out_stream,
                     ap_uint<256> key,
                     ap_uint<32> msg_len)
{
#pragma HLS INTERFACE axis port=in_stream
#pragma HLS INTERFACE axis port=out_stream
#pragma HLS INTERFACE s_axilite port=key bundle=control
#pragma HLS INTERFACE s_axilite port=msg_len bundle=control
#pragma HLS INTERFACE s_axilite port=return bundle=control

    ogayImpl::hmac_sha256_ctx ctx;
    uint8_t key_bytes[SHA256_DIGEST_SIZE];
    uint8_t mac[SHA256_DIGEST_SIZE];

#pragma HLS ARRAY_PARTITION variable=key_bytes complete dim=1
#pragma HLS ARRAY_PARTITION variable=mac complete dim=1

    for (int i = 0; i < SHA256_DIGEST_SIZE; ++i) {
#pragma HLS UNROLL
        key_bytes[i] = (uint8_t)key.range(255 - (i * 8), 248 - (i * 8));
    }

    ogayImpl::hmac_sha256_init(&ctx, key_bytes, SHA256_DIGEST_SIZE);

    ap_uint<32> bytes_seen = 0;
    stream_t in_pkt;

    do {
#pragma HLS PIPELINE II=1
        in_pkt = in_stream.read();
        ap_uint<32> word = in_pkt.data;

        for (int byte_idx = 0; byte_idx < 4; ++byte_idx) {
#pragma HLS UNROLL
            if (bytes_seen < msg_len) {
                uint8_t byte = (uint8_t)((word >> (24 - (byte_idx * 8))) & 0xff);
                ogayImpl::hmac_sha256_update(&ctx, &byte, 1);
                ++bytes_seen;
            }
        }
    } while (in_pkt.last == 0);

    ogayImpl::hmac_sha256_final(&ctx, mac, SHA256_DIGEST_SIZE);

    for (int word_idx = 0; word_idx < 8; ++word_idx) {
#pragma HLS PIPELINE II=1
        stream_t out_pkt;
        ap_uint<32> word = 0;

        word.range(31, 24) = mac[(word_idx * 4) + 0];
        word.range(23, 16) = mac[(word_idx * 4) + 1];
        word.range(15, 8) = mac[(word_idx * 4) + 2];
        word.range(7, 0) = mac[(word_idx * 4) + 3];

        out_pkt.data = word;
        out_pkt.keep = 0xf;
        out_pkt.strb = 0xf;
        out_pkt.last = (word_idx == 7) ? 1 : 0;
        out_stream.write(out_pkt);
    }
}