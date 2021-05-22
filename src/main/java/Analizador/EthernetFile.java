package Analizador;

/* interfaz 2*/
import com.sun.jna.Platform;
import java.io.IOException;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.util.ByteArrays;
import org.pcap4j.util.NifSelector;

@SuppressWarnings("javadoc")
public class EthernetFile {

    private static int COUNT = 32;
    private static final String PCAP_FILE_KEY = LLCFile.class.getName() + ".pcapFile";
    private static String PCAP_FILE = System.getProperty(PCAP_FILE_KEY, "paquetes3.pcap");

  public EthernetFile() {}

  public void getEthernetFile(int numTrama, String FileRoute) throws PcapNativeException, NotOpenException {
    COUNT = numTrama;
    PCAP_FILE = FileRoute;

    PcapHandle handle;
        try {
            handle = Pcaps.openOffline(PCAP_FILE, PcapHandle.TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(PCAP_FILE);
        }

    for (int i = 0; i < COUNT; i++) {
      byte[] packet = handle.getNextRawPacket();
      if (packet == null) {
        continue;
      } else {
        System.out.println(handle.getTimestamp());
        System.out.println(ByteArrays.toHexString(packet, " "));
        for(int j=0;j<packet.length;j++){
            System.out.printf("%02X ",packet[j]);
            if(j%16==0)
                System.out.println("");
        }//for
          System.out.println("\n");
      }
    }

    handle.close();
  }
}