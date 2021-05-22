package Analizador;

/* interfaz 6*/
import com.sun.jna.Platform;
import java.io.IOException;
import java.util.Arrays;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.NifSelector;
import org.pcap4j.packet.IpV4Packet;

@SuppressWarnings("javadoc")
public class IPTrama {

  private static final String COUNT_KEY = IPTrama.class.getName() + ".count";
  private static int COUNT = Integer.getInteger(COUNT_KEY, 5);

  private static final String READ_TIMEOUT_KEY = IPTrama.class.getName() + ".readTimeout";
  private static final int READ_TIMEOUT = Integer.getInteger(READ_TIMEOUT_KEY, 10); // [ms]

  private static final String SNAPLEN_KEY = IPTrama.class.getName() + ".snaplen";
  private static final int SNAPLEN = Integer.getInteger(SNAPLEN_KEY, 65536); // [bytes]

  private static final String BUFFER_SIZE_KEY = IPTrama.class.getName() + ".bufferSize";
  private static final int BUFFER_SIZE = Integer.getInteger(BUFFER_SIZE_KEY, 1 * 1024 * 1024); // [bytes]

  private static final String NIF_NAME_KEY = IPTrama.class.getName() + ".nifName";
  private static final String NIF_NAME = System.getProperty(NIF_NAME_KEY);

  public IPTrama() {}

  public void getIP(int numTramas) throws PcapNativeException, NotOpenException {
    String filter = "";
     COUNT = numTramas;
    /*System.out.println(COUNT_KEY + ": " + COUNT);
    System.out.println(READ_TIMEOUT_KEY + ": " + READ_TIMEOUT);
    System.out.println(SNAPLEN_KEY + ": " + SNAPLEN);
    System.out.println(BUFFER_SIZE_KEY + ": " + BUFFER_SIZE);
    System.out.println(NIF_NAME_KEY + ": " + NIF_NAME);
    System.out.println("\n");*/
    
      System.out.println("Seleccione la interfaz");
      PcapNetworkInterface nif;
      if (NIF_NAME != null) {
          nif = Pcaps.getDevByName(NIF_NAME);
      }else {
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

    PcapHandle handle =
        new PcapHandle.Builder(nif.getName())
            .snaplen(SNAPLEN)
            .promiscuousMode(PromiscuousMode.PROMISCUOUS)
            .timeoutMillis(READ_TIMEOUT)
            .bufferSize(BUFFER_SIZE)
            .build();

    handle.setFilter(filter, BpfCompileMode.OPTIMIZE);

    int num = 0;
    while (true) {  
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
        num++;
        if (num >= COUNT) {
          break;
        }
      }
    }

    PcapStat ps = handle.getStats();
    System.out.println("ps_recv: " + ps.getNumPacketsReceived());
    System.out.println("ps_drop: " + ps.getNumPacketsDropped());
    System.out.println("ps_ifdrop: " + ps.getNumPacketsDroppedByIf());
    if (Platform.isWindows()) {
      System.out.println("bs_capt: " + ps.getNumPacketsCaptured());
    }

    handle.close();
  }
}