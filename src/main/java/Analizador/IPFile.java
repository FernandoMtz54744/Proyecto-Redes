package Analizador;

/* interfaz 6*/
import com.sun.jna.Platform;
import java.util.Arrays;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;

@SuppressWarnings("javadoc")
public class IPFile {

    private static int COUNT = 32;
    private static final String PCAP_FILE_KEY = LLCFile.class.getName() + ".pcapFile";
    private static String PCAP_FILE = System.getProperty(PCAP_FILE_KEY, "paquetes3.pcap");
    
  public IPFile() {}

  public void getIPFIle(int numTramas, String FileRoute) throws PcapNativeException, NotOpenException {
    String filter = "";
     COUNT = numTramas;
     PCAP_FILE = FileRoute;
     
     PcapHandle handle;
        try {
            handle = Pcaps.openOffline(PCAP_FILE, PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(PCAP_FILE);
        }
     
    int num = 0;
    
    for (int i = 0; i < COUNT; i++) {  
      byte[] packet = handle.getNextRawPacket();
        
      if (packet == null) {
        continue;
      } else {
        System.out.println(handle.getTimestamp());
        //System.out.println(ByteArrays.toHexString(packet, " "));
        for(int j=0;j<packet.length;j++){
            System.out.printf("%02X ",packet[j]);
            if(j%16==0)
                System.out.println("");
        }
        
         //Obteniendo el tipo de protocolo
        int tipo_b1= (packet[12]>=0?packet[12]*256:(packet[12]+256)*256);
        int tipo_b2= packet[13]>=0?packet[13]:packet[12]+256;
        int tipo = tipo_b1+tipo_b2;
        System.out.println("\nTipo: " +tipo);
        
        if(tipo==2048){
            int ihl = (packet[14]&0x0f)*4;
            System.out.println("Size: " + ihl);
            try {
                byte[] tmp_ip = Arrays.copyOfRange(packet, 14, 14+ihl);
                IpV4Packet ip = IpV4Packet.newPacket(tmp_ip, 0, tmp_ip.length);
                
                System.out.println("Version: " + ip.getHeader().getVersion().valueAsString());
                System.out.println("IHL: " + ip.getHeader().getIhlAsInt());
                System.out.println("Serv. Dif: " + ip.getHeader().getTos().toString());
                int lt = (ip.getHeader().getTotalLength()>0)?ip.getHeader().getTotalLength():ip.getHeader().getTotalLength()+65536;
                System.out.println("Longitud total: "+lt);
                int id = (ip.getHeader().getIdentification()>0)?ip.getHeader().getIdentification():ip.getHeader().getIdentification()+65536;
                System.out.println("Id: "+id);
                System.out.println("Flags: ");
                System.out.println("-More Fragments: " + ip.getHeader().getMoreFragmentFlag());
                System.out.println("-Don't Fragment: " + ip.getHeader().getDontFragmentFlag());
                int fragOff = ip.getHeader().getFragmentOffset()>=0?ip.getHeader().getFragmentOffset():ip.getHeader().getFragmentOffset()+8192;
                System.out.println("Fragment offset: " + fragOff);
                System.out.println("TTL: " + ip.getHeader().getTtlAsInt());
                System.out.println("Protocolo: "+ ip.getHeader().getProtocol());
                int checksum = ip.getHeader().getHeaderChecksum()>=0?ip.getHeader().getHeaderChecksum():ip.getHeader().getHeaderChecksum()+65536;
                System.out.println("Checksum: " + checksum);
                System.out.println("IP Origen: " + ip.getHeader().getSrcAddr());
                System.out.println("IP Destino: " + ip.getHeader().getDstAddr());
                //System.out.println("Opciones: " + ip.getHeader().getOptions());

            } catch (Exception ex) {
                System.out.println("Error crear IpV4Packet: " + ex.getMessage());
            }
            
        }
        
        System.out.println("");
      }
    }

    handle.close();
  }
}