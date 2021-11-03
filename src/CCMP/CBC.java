package CCMP;

import java.util.Arrays;

public class CBC {
    byte[][] header;
    byte[][] payload;
    byte[] IV;
    byte[] nonce;
    String temporal_key;

    public CBC(byte[][] header, byte[][] payload, byte[] nonce, String temporal_key) {
        this.header = header;
        this.payload = payload;
        IV = new byte[16];
        System.arraycopy(nonce, 0, IV, 0, nonce.length);
        this.nonce = nonce;
        this.temporal_key = temporal_key;
    }

    byte[] XOR(byte[] array1, byte[] array2){
        byte[] xor = new byte[array1.length];
        int i = 0;
        for (byte b : array1)
            xor[i] = (byte)(b ^ array2[i++]);
        return xor;
    }

    byte[] calculate_MIC(){
        byte[] cipher_block;
        byte[] IV_AES = AES.encrypt(IV, temporal_key);
        cipher_block = AES.encrypt(this.XOR(header[0], IV_AES),temporal_key);
        for(int i=1; i<header.length; i++){
            cipher_block = AES.encrypt(this.XOR(header[i], cipher_block),temporal_key);
        }
        for (byte[] bytes : payload) {
            cipher_block = AES.encrypt(this.XOR(bytes, cipher_block), temporal_key);
        }
        assert cipher_block != null;
        byte[] MAC = Arrays.copyOf(cipher_block, 8);
        byte [] MIC = new byte[16];
        System.arraycopy(MAC, 0, MIC, 0, MAC.length);
        byte[] Ctr_preload_0 = new byte[16];
        System.arraycopy(nonce, 0, Ctr_preload_0, 0, nonce.length);
        Ctr_preload_0 = AES.encrypt(Ctr_preload_0, temporal_key);
        assert Ctr_preload_0 != null;
        MIC = XOR(Ctr_preload_0, MIC);
        return MIC;
    }

}
