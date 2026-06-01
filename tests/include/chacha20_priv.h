#ifdef UNIT_TEST
void initialize_chacha_state(uint32_t *state, const uint8_t *key_w, const uint8_t *nonce_w, uint32_t block_ctr);
void quarter_round(uint32_t *state, int i0, int i1, int i2, int i3);
void serialize_state(uint8_t *out, uint32_t *state);
#endif