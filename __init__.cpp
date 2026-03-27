 #include <string>

 class ChaCha20Poly1305 {
    public:
        unsigned char key[32];
        int nonceLength;
        int tagLength;
        bool isBlockCipher;
        bool isAEAD;
        string name;

        ChaCha20Poly1305(unsigned char key[32]) {   
            nonceLength = 12;
            tagLength = 16;
            isBlockCipher = false;
            isAEAD = true;
            name = "chacha20-poly1305";
        }
};