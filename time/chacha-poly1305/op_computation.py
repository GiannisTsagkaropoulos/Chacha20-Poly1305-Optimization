import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import chacha.op_computation as chacha_op
import poly1305.op_computation as poly1305_op

#TODO: Replace dummy data with actual op count

def get_aead_encrypt_baseline_complexity(plaintext_len: int, aad_len: int = 0):
    total_ops = 2 +  1 + 2 + 8 + 10

    chacha_ops = chacha_op.get_chacha20_encrypt_baseline_complexity(plaintext_len)

    pad_aad_len = (16 - (aad_len % 16)) % 16
    pad_ctxt_len = (16 - (plaintext_len % 16)) % 16
    mac_data_len = aad_len + pad_aad_len + plaintext_len + pad_ctxt_len + 16

    poly_init_ops = poly1305_op.get_poly1305_init_baseline_complexity()
    poly_ops = poly1305_op.get_create_tag1305_baseline_complexity(mac_data_len)
     
    total_ops += chacha_ops + poly_init_ops + poly_ops

    return total_ops

def get_aead_encrypt_best_scalar_complexity(plaintext_len: int, aad_len: int = 0):
    total_ops = 2 +  1 + 2 + 8 + 10

    chacha_ops = chacha_op.get_chacha20_encrypt_unroll_ilp_ctxt_complexity(plaintext_len)

    pad_aad_len = (16 - (aad_len % 16)) % 16
    pad_ctxt_len = (16 - (plaintext_len % 16)) % 16
    mac_data_len = aad_len + pad_aad_len + plaintext_len + pad_ctxt_len + 16

    poly_init_ops = poly1305_op.get_poly1305_init_precompute_clamp_masks_complexity()
    poly_ops = poly1305_op.get_create_tag1305_baseline_complexity(mac_data_len)
     
    total_ops += chacha_ops + poly_init_ops + poly_ops

    return total_ops

def get_aead_encrypt_best_vectorized_complexity(plaintext_len: int, aad_len: int = 0):
    total_ops = 2 +  1 + 2 + 8 + 10

    chacha_ops = chacha_op.get_chacha20_encrypt_vectorized3_complexity(plaintext_len)

    pad_aad_len = (16 - (aad_len % 16)) % 16
    pad_ctxt_len = (16 - (plaintext_len % 16)) % 16
    mac_data_len = aad_len + pad_aad_len + plaintext_len + pad_ctxt_len + 16

    poly_init_ops = poly1305_op.get_poly1305_init_vectorized_complexity()
    poly_ops = poly1305_op.get_memory_vect_inlined_carry_delay_parallel_Horner_complexity(mac_data_len)
     
    total_ops += chacha_ops + poly_init_ops + poly_ops

    return total_ops

def get_aead_encrypt_openssl_complexity(plaintext_len: int, aad_len: int = 0):
    total_ops = 2 +  1 + 2 + 8 + 10

    chacha_ops = chacha_op.get_chacha20_encrypt_openssl_complexity(plaintext_len)

    pad_aad_len = (16 - (aad_len % 16)) % 16
    pad_ctxt_len = (16 - (plaintext_len % 16)) % 16
    mac_data_len = aad_len + pad_aad_len + plaintext_len + pad_ctxt_len + 16

    poly_init_ops = poly1305_op.get_poly1305_init_vectorized_complexity()
    poly_ops = poly1305_op.get_poly1305_create_tag_openssl_complexity(mac_data_len)
     
    total_ops += chacha_ops + poly_init_ops + poly_ops

    return total_ops