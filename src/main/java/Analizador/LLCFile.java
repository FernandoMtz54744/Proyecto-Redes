package Analizador;

//Martinez Martinez Fernando; Cortes Lopez Jaime Alejandro

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;

@SuppressWarnings("javadoc")
public class LLCFile {

    private static int COUNT = 32;
    private static final String PCAP_FILE_KEY = LLCFile.class.getName() + ".pcapFile";
    private static String PCAP_FILE = System.getProperty(PCAP_FILE_KEY, "paquetes3.pcap");

    public void LLC() {}

    public void getLLC_File(int numTramas, String FileRoute) throws PcapNativeException, NotOpenException {
        COUNT = numTramas;
        PCAP_FILE = FileRoute;
        
        PcapHandle handle;
        try {
            handle = Pcaps.openOffline(PCAP_FILE, TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(PCAP_FILE);
        }

        for (int i = 0; i < COUNT; i++) {
            try {
                byte[] packet = handle.getNextRawPacket();
                for (int j = 0; j < packet.length; j++) {
                    if (j % 16 == 0) {
                        System.out.println("");
                    }
                    System.out.printf("%02X ", packet[j]);
                }

                //Imprimiendo datos de la trama
                System.out.println("\nDatos de la trama:");
                System.out.print("MAC destino: ");
                for(int j=0; j<6; j++){
                    System.out.printf("%02X ", packet[j]);
                }
                System.out.print("\nMAC Origen: ");
                for(int j=6; j<12; j++){
                    System.out.printf("%02X ", packet[j]);
                }
          
                int longitud = (packet[12]*256) + (packet[13]>=0?packet[13]:256+packet[13]);
                System.out.printf("\nLongitud: %02X %02X -> %d\n", packet[12], packet[13],longitud);    
                
                if( longitud < 1500){
                    System.out.println("Tipo: IEE 802.3");
                    
                    System.out.printf("DSAP: %02X - ", packet[14]);
                    int i_g = packet[14]&0x01;
                    System.out.println(i_g==0?"Individual":"Grupal");
                    
                    System.out.printf("SSAP: %02X - ", packet[15]);
                    int c_r = packet[15]&0x01;
                    System.out.println(c_r==0?"Comando":"Respuesta");  
                    
                    if(longitud > 3){   
                        System.out.println("Control en modo extendido");
                        //Control en modo extendido (2 bytes) [16-17]
                        System.out.printf("Control: %02X %02X -> ", packet[16], packet[17]);
                        System.out.println(String.format("%8s", Integer.toBinaryString(packet[16])).replace(" ", "0") + " " + String.format("%8s", Integer.toBinaryString(packet[17])).replace(" ", "0"));
                        int c = packet[16]&0x01;
                        if(c == 0){ //Trama I
                            System.out.println("Trama I");
                            int nsec = (packet[16]>>1)&0x7F;    
                            System.out.println("No_Secuencia: " + String.format("%7s", Integer.toBinaryString(nsec)).replace(" ", "0") + " -> " +nsec);
                            int nack = (packet[17]>>1)&0x7F;
                            System.out.println("No_Acuse: " + String.format("%7s", Integer.toBinaryString(nack)).replace(" ", "0") + " -> " +nack);     
                        }else{
                            c = (packet[16]>>1)&0x01;
                            if(c==0){
                                System.out.println("Trama S");
                                 int no_sup = (packet[16]>>2)&0x03;
                                 System.out.print("No_Sup: " + String.format("%2s", Integer.toBinaryString(no_sup)).replace(" ", "0") + " -> " +no_sup + " ");
                                 if (no_sup == 0) {
                                    System.out.println("(Listo para recibir)");
                                } else {
                                    if (no_sup == 1) {
                                        System.out.println("(Rechazo)");
                                    } else {
                                        if (no_sup == 2) {
                                            System.out.println("(Receptor no listo para recibir)");
                                        } else {
                                            System.out.println("(Rechazo selectivo)");
                                        }
                                    }
                                }
                                 
                                 int nack = (packet[17]>>1)&0x7F;
                                 System.out.println("No_Acuse: " + String.format("%7s", Integer.toBinaryString(nack)).replace(" ", "0") + " -> " +nack);
                            }else{
                                System.out.println("Trama U");
                                int u1 = (packet[16]>>2)&0x03;
                                int u2 = (packet[16]>>5)&0x07;
                                System.out.println("U1: " + String.format("%2s",Integer.toBinaryString(u1)).replace(" ", "0"));
                                System.out.println("U2: " + String.format("%3s",Integer.toBinaryString(u2)).replace(" ", "0"));
                            }
                        }
                    }else{
                        //Control modo normal (1 byte) [16]
                        System.out.println("Control en modo normal");
                        System.out.printf("Control: %02X -> ", packet[16]);
                        System.out.println(String.format("%8s", Integer.toBinaryString(packet[16])).replace(" ", "0"));
                        int c = packet[16]&0x01;
                        if(c==0){
                            System.out.println("Trama I");
                            int nsec = (packet[16]>>1)&0x07;
                            System.out.println("No_sec: " + String.format("%3s", Integer.toBinaryString(nsec)).replace(" ","0") + " -> " + nsec);
                            int nack = (packet[16]>>5)&0x07;
                            System.out.println("No_Acuse: " + String.format("%3s", Integer.toBinaryString(nack)).replace(" ","0") + " -> " + nack);
                        }else{
                           c = (packet[16]>>1)&0x01;
                           if(c==0){
                               System.out.println("Trama S");
                               int no_sup = (packet[16]>>2)&0x03;   
                               System.out.print("No_Sup: " + String.format("%2s", Integer.toBinaryString(no_sup)).replace(" ", "0") + " -> " +no_sup + " ");
                                if (no_sup == 0) {
                                    System.out.println("(Listo para recibir)");
                                } else {
                                    if (no_sup == 1) {
                                        System.out.println("(Rechazo)");
                                    } else {
                                        if (no_sup == 2) {
                                            System.out.println("(Receptor no listo para recibir)");
                                        } else {
                                            System.out.println("(Rechazo selectivo)");
                                        }
                                    }
                                }
                               int nack = (packet[16]>>5)&0x07;
                               System.out.println("No_Acuse: " + String.format("%3s", Integer.toBinaryString(nack)).replace(" ", "0") + " -> " +nack);
                           }else{
                               System.out.println("Trama U");
                               int u1 = (packet[16]>>2)&0x03;
                               int u2 = (packet[16]>>5)&0x07;
                               System.out.println("U1: " + String.format("%2s",Integer.toBinaryString(u1)).replace(" ", "0"));
                               System.out.println("U2: " + String.format("%3s",Integer.toBinaryString(u2)).replace(" ", "0"));
                           }
                        }
                    }
                    
                    
                }else{
                    System.out.println("Tipo: Ethernet");

                }
                
                
                
                
            } catch (Exception e) {
                System.out.println("Error al leer tramas: " + e.getMessage());
            }
        }

        handle.close();
    }
}
