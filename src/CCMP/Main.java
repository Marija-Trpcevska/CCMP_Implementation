package CCMP;

import java.security.SecureRandom;

public class Main {

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
    public static void print_byte_array(byte[] array){
        for (byte b : array) {
            System.out.print(String.format("%x",b) + " ");
        }
        System.out.println("\n");
    }
    public static void main(String[] args) {
        ClearTextFrame frame = new ClearTextFrame("dp...st.:.T...E.....@.)....w.....e.P..S...u'qYP.......HTTP/1.1 200 OK..Date: Sun, 31 Oct 2021 15:47:41 GMT..Server: Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.25 mod_perl/2.0.11 Perl/v5.16.3..Last-Modified: Sun, 31 Oct 2021 05:59:02 GMT..ETag: \"80-5cf9fc1d3fb42\"..Accept-Ranges: bytes..Content-Length: 128..Keep-Alive: timeout=5, max=100..Connection: Keep-Alive..Content-Type: text/html; charset=UTF-8....<html>.Congratulations.  You've downloaded the file.http://gaia.cs. umass.edu/wireshark-labs/HTTP-wireshark-file1.html!.</html>.");
        frame.print_packet_in_blocks();

        byte[] PN = new byte[6];
        SecureRandom random = new SecureRandom();
        random.nextBytes(PN);

        String source_MAC_string_hex = "74ea3ad9549e";
        byte[] source_MAC = hexStringToByteArray(source_MAC_string_hex);

        String QOS_string = "28";
        byte[] QOS = hexStringToByteArray(QOS_string);

        byte[] nonce = new byte[13];
        int i, j;
        for(i=0,j=0; j<PN.length; i++,j++){
            nonce[i] = PN[j];
        }
        for(j=0; j<source_MAC.length; i++,j++){
            nonce[i] = source_MAC[j];
        }
        for(j=0; j<QOS.length; i++,j++){
            nonce[i] = QOS[j];
        }

        System.out.println("PACKET NUMBER:\n");
        print_byte_array(PN);
        System.out.println("SOURCE MAC:\n");
        print_byte_array(source_MAC);
        System.out.println("QUALITY OF SERVICE:\n");
        print_byte_array(QOS);
        System.out.println("NONCE:\n");
        print_byte_array(nonce);

        String temporal_key = "OVERLORD";
        AES.setKey(temporal_key);

        CBC cbc_mode_encrypt = new CBC(frame.header_128, frame.payload_128, nonce, temporal_key);
        byte[] MIC = cbc_mode_encrypt.calculate_MIC();
        System.out.println("MIC:\n");
        print_byte_array(MIC);

        CTR ctr_mode_encrypt = new CTR(frame.payload_128, nonce, temporal_key);
        byte[][] encrypted_payload = new byte[0][];
        try {
            encrypted_payload = ctr_mode_encrypt.encrypt_payload();
        }
        catch (CTR.FailedEncryptionDecryption ex){
            System.out.println(ex.getMessage());
        }

        EncryptedTextFrame encrypted_frame = new EncryptedTextFrame(nonce,temporal_key,frame.header_128, encrypted_payload, MIC);
        System.out.println("ENCRYPTED PAYLOAD:\n");
        encrypted_frame.print_payload(encrypted_frame.payload);

        CTR ctr_mode_decrypt = new CTR(encrypted_frame.payload, nonce, temporal_key);
        byte[][] decrypted_payload = new byte[0][];
        try {
            decrypted_payload = ctr_mode_decrypt.encrypt_payload();
        }
        catch (CTR.FailedEncryptionDecryption ex){
            System.out.println(ex.getMessage());
        }

        System.out.println("DECRYPTED PAYLOAD:\n");
        encrypted_frame.print_payload(decrypted_payload);

        CBC cbc_mode_decrypt = new CBC(encrypted_frame.header, decrypted_payload, nonce, temporal_key);
        byte[] MIC_new = cbc_mode_decrypt.calculate_MIC();

        System.out.println("MIC:\n");
        print_byte_array(MIC_new);

        try{
            encrypted_frame.compare_MICs(MIC_new);
        }catch (EncryptedTextFrame.CompromisedIntegrity ex){
            System.out.println(ex.getMessage());
        }

    }
}
