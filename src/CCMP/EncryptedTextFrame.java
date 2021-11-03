package CCMP;

public class EncryptedTextFrame {

    public static class CompromisedIntegrity extends Exception {
        public CompromisedIntegrity(String errorMessage) {
            super(errorMessage);
        }
    }
    byte[] nonce;
    String temporal_key;
    byte[][] header;
    byte[][] payload;
    byte[] MIC;

    public EncryptedTextFrame(byte[] nonce, String temporal_key,byte[][] header, byte[][] payload, byte[] MIC) {
        this.nonce = nonce;
        this.temporal_key = temporal_key;
        this.header = header;
        this.payload = payload;
        this.MIC = MIC;
    }
    void print_payload(byte[][] payload){
        for (byte[] bytes : payload) {
            for (int j = 0; j < payload[0].length; j++) {
                System.out.print(String.format("%x",bytes[j])+ " ");
            }
            System.out.println();
        }
        System.out.println("\n");
    }

    void compare_MICs(byte[] MIC_new) throws CompromisedIntegrity{
        if(!(java.util.Arrays.equals(MIC_new, MIC)))
            throw new CompromisedIntegrity("INTEGRITY COMPROMISED");
    }

}
