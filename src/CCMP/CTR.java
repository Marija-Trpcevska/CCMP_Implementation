package CCMP;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class CTR {
    public static class FailedEncryptionDecryption extends Exception {
        public FailedEncryptionDecryption(String errorMessage) {
            super(errorMessage);
        }
    }

    byte[][] payload;
    byte[] nonce;
    byte[] counter = {0,0,1};
    String temporal_key;

    public CTR(byte[][] payload, byte[] nonce, String temporal_key) {
        this.payload = payload;
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

    public static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
    byte[][] encrypt_payload() throws FailedEncryptionDecryption {
        byte[][] encrypted_payload;
        if(temporal_key == null || nonce == null || payload == null )
            throw new FailedEncryptionDecryption("ATTEMPTED ENCRYPTION/DECRYPTION FAILED");
        else{
            encrypted_payload = new byte[payload.length][payload[0].length];
            byte[] Ctr_preload;
            byte[] counter_4_bytes = {0,0,0,1};
            int count;
            for(int i=0; i<payload.length; i++){
                Ctr_preload = AES.encrypt(concat(nonce, counter), temporal_key);
                assert Ctr_preload != null;
                encrypted_payload[i] = XOR(Ctr_preload, payload[i]);
                count = ByteBuffer.wrap(counter_4_bytes).getInt()+1;
                counter_4_bytes = ByteBuffer.allocate(4).putInt(count).array();
                counter = Arrays.copyOfRange(counter_4_bytes, 1,4);
            }
        }
        return encrypted_payload;
    }


}
