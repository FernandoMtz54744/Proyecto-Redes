package Analizador;

import java.io.IOException;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.NifSelector;



@SuppressWarnings("javadoc")
public class ARPTrama {

   private static final String COUNT_KEY = ARPTrama.class.getName() + ".count";
  private static int COUNT = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY = ARPTrama.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = ARPTrama.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private static final String BUFFER_SIZE_KEY = ARPTrama.class.getName() + ".bufferSize";
  private static final int BUFFER_SIZE = Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024); // [bytes]

  private static final String NIF_NAME_KEY = ARPTrama.class.getName() + ".nifName";
  private static final String NIF_NAME = System.getProperty(NIF_NAME_KEY);

    public ARPTrama() {}

    public void getARPTrama(int numTramas) throws PcapNativeException, NotOpenException {
        String filter = "";
        COUNT = numTramas;
        
        System.out.println("Seleccione la interfaz");
        PcapNetworkInterface nif;
        if (NIF_NAME != null) {
            nif = Pcaps.getDevByName(NIF_NAME);
        } else {
            try {
                nif = new NifSelector().selectNetworkInterface();
            } catch (IOException e) {
                System.out.println("Error interfaz: " + e.getMessage());
                return;
            }
            if (nif == null) {
                return;
            }
        }

        System.out.println(nif.getName() + " (" + nif.getDescription() + ")");

        for (PcapAddress addr : nif.getAddresses()) {
            if (addr.getAddress() != null) {
                System.out.println("IP address: " + addr.getAddress());
            }
        }
        System.out.println("");

        PcapHandle handle
                = new PcapHandle.Builder(nif.getName())
                        .snaplen(SNAPLEN)
                        .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                        .timeoutMillis(READ_TIMEOUT)
                        .bufferSize(BUFFER_SIZE)
                        .build();

        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        
         int num = 0;
            while (true) {
                byte[] packet = handle.getNextRawPacket();
                
                if (packet == null) {
                    continue;
                } else {   
                    try {
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
                                 
                        System.out.println("");
                        num++;
                        if (num >= COUNT) {
                            break;
                        }
                        
                        } else{
                            System.out.println("Trama IEEE 802.3");
                        }

                    } catch (Exception e) {
                        System.out.println("Error al leer tramas: " + e.getMessage());
                      }
                }
        
        }
        handle.close();
    
}
}
