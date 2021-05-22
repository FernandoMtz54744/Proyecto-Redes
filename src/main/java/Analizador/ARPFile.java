package Analizador;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;



@SuppressWarnings("javadoc")
public class ARPFile {

    private static int COUNT = 15;

    private static final String PCAP_FILE_KEY = ARPFile.class.getName() + ".pcapFile";
    private static  String PCAP_FILE = System.getProperty(PCAP_FILE_KEY, "ARP.pcap");

    public ARPFile() {}

    public void getARPFile(int numTramas, String FileRoute) throws PcapNativeException, NotOpenException {
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
                byte[]  packet = handle.getNextRawPacket();
               
                
                
                for (int j = 0; j < packet.length; j++) {
                 if (j % 16 == 0) {
                System.out.println("");
                    }
                    System.out.printf("%02X ", packet[j]);
                }
                 //Imprimiendo datos de la trama
                System.out.println("\nDatos de la trama:");
                System.out.print("->MAC destino: ");
                for(int j=0; j<6; j++){
                    System.out.printf("%02X ", packet[j]);
                }
                System.out.printf("\n->MAC Origen: ");
                for(int j=6; j<12; j++){
                    System.out.printf("%02X ", packet[j]);
                }
                int longitud = (packet[12]*256) + (packet[13]>=0?packet[13]:256+packet[13]);
                System.out.printf("\n->Tipo: %d (%04X) \n", longitud ,longitud);
                
                if(longitud >= 1500){
                    System.out.println("->Trama Ethernet");
                     int tipo =  (packet[12]*256) + (packet[13]>=0?packet[13]:256+packet[13]);
                     //Verificando tramas con  protocolo ARP
                     if(tipo == 2054){
                    int hardware_type = (packet[14]*256) + (packet[15]>=0?packet[15]:256+packet[15]);
                    //Tipo de Hardware
                         System.out.printf("->Valor HRD: %d", hardware_type);
                         switch (hardware_type){
                             case 1:
                                 System.out.printf("\n->Tipo de Hardware: Ethernet");
                                 break;
                             case 6:
                                 System.out.printf("->Tipo de Hardware: IEEE 802 Networks");
                                 break;
                              case 7:
                                 System.out.printf("->Tipo de Hardware: ARCNET");
                                 break;
                               case 15:
                                 System.out.printf("->Tipo de Hardware: Frame Relay");
                                 break;
                               case 16:
                                 System.out.printf("->Tipo de Hardware: Asynchronous Transfer Mode (ATM)");
                                 break;
                               case 17:
                                 System.out.printf("->Tipo de Hardware: HDLC");
                                 break;
                                case 18:
                                 System.out.printf("->Tipo de Hardware: Fibre Channel");
                                 break;
                                 case 19:
                                 System.out.printf("->Tipo de Hardware: Asynchronous Transfer Mode (ATM)");
                                 break;
                                 case 20:
                                 System.out.printf("->Tipo de Hardware: Serial Line");
                                 break;
                         }
                         }
                   int protocole_type =  (packet[16]*256) + (packet[17]>=0?packet[17]:256+packet[17]);  
                   //Tipo de protocolo
                         if(protocole_type == 2048){
                             System.out.printf("\n->Tipo de protocolo: %d (%04X)", protocole_type,protocole_type);
                             System.out.printf("\n->Longitud de direccion de Hardware: %d", packet[18]); //6
                             System.out.printf("\n->Longitud de dirección de protocolo: %d",packet[19]); //4
                             //Código de operacion
                             int opcode = (packet[20]*256) + (packet[21]>=0?packet[21]:256+packet[21]); 
                             System.out.printf("\n->Codigo de operacion: %d", opcode);
                             switch (opcode){
                             case 1:
                                 System.out.println("\n->Tipo de mensaje ARP: ARP Request");
                                 break;
                              case 2:
                                 System.out.println("\n->Tipo de mensaje ARP: ARP Reply");
                                 break;
                              case 3:
                                 System.out.println("\n->Tipo de mensaje ARP: RARP Request");
                                 break;
                               case 4:
                                 System.out.println("->Tipo de mensaje ARP: RARP Reply");
                                 break;
                }
                             //Direccion MAC del emisor
                             System.out.printf("->Direccion MAC del emisor: ");
                             for(int j=22; j<28; j++){
                             System.out.printf("%02X ", packet[j]);
                }
                             System.out.printf("\n->Direccion IP sender:  %d . %d . %d . %d",(packet[28]>=0?packet[28]:256+packet[28]),(packet[29]>=0?packet[29]:256+packet[29]),(packet[30]>=0?packet[30]:256+packet[30]),(packet[31]>=0?packet[31]:256+packet[31]));

                             System.out.printf("\n->Direccion MAC del destinatario:"); //000000
                             for(int j=32; j<38; j++){
                             System.out.printf("%02X ", packet[j]);
                }
                             System.out.printf("\n->Direccion IP destino: %d . %d . %d . %d \n\n", (packet[38]>=0?packet[38]:256+packet[38]),(packet[39]>=0?packet[39]:256+packet[39]),(packet[40]>=0?packet[40]:256+packet[40]),(packet[41]>=0?packet[41]:256+packet[41]));
                             
                }
                } else{
                    System.out.println("Trama IEEE 802.3");
                }
                            
            } catch (Exception e) {
                System.out.println("Error al leer tramas: " + e.getMessage());
                    }
        
        }
        handle.close();
    
}
}
