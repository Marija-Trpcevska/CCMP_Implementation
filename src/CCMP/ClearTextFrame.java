package CCMP;

import java.nio.charset.StandardCharsets;


public class ClearTextFrame {
    byte[][] header_128;
    byte[][] payload_128;

    public ClearTextFrame(String packet) {
        byte[] header = packet.substring(0, 14).getBytes(StandardCharsets.UTF_8);
        byte[] payload = packet.substring(15).getBytes(StandardCharsets.UTF_8);
        this.header_128 = this.Separate_in_128_bit_blocks(header);
        this.payload_128 = this.Separate_in_128_bit_blocks(payload);
    }

    byte[][] Separate_in_128_bit_blocks(byte[] array){
        int l = array.length;
        int m = (l % 16 == 0) ? l/16 : l/16+1;
        byte[][] array_128 = new byte[m][16];
        int k=0, i, j;
        for( i=0; i<m-1; i++){
            for(j=0; j<16;j++){
                array_128[i][j] = array[k];
                k++;
            }
        }
        int n = l - k;
        if(l-k != 16){
            for(j=0; j<n; j++){
                array_128[i][j] = array[k];
                k++;
            }
        }
        else{
            for(j=0; j<16; j++){
                array_128[i][j] = array[k];
                k++;
            }
        }
        return array_128;
    }

    void print_packet_in_blocks(){
        System.out.println("DATA SEPARATED INTO CHUNKS:\n");
        System.out.println("ASSOCIATED DATA:\n");
        for (byte[] bytes : header_128) {
            for (int j = 0; j < header_128[0].length; j++) {
                System.out.print(String.format("%x",bytes[j])+ " ");
            }
            System.out.println();
        }
        System.out.println("\n");
        System.out.println("PAYLOAD:\n");
        for (byte[] bytes : payload_128) {
            for (int j = 0; j < payload_128[0].length; j++) {
                System.out.print(String.format("%x",bytes[j])+ " ");
            }
            System.out.println();
        }
        System.out.println("\n");
    }
}




