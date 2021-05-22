package Analizador;

import java.util.Scanner;

public class Main {
    
   public static void main(String[] args) {
        mostrar_menu();
   
   }
    

    
public static void mostrar_menu() {
        Scanner lector = new Scanner(System.in);
        int opcion, numTramas;
        String FileRoute;
        
        do {
            System.out.println("----------------------------------------------");
            System.out.println("Elija una opción:");
            System.out.println("1) Iniciar captura de tramas al vuelo");
            System.out.println("2) Cargar traza de captura desde archivo");
            opcion = lector.nextInt();
            System.out.println("");
            int opc = seleccionarFiltro();
            System.out.println("Cuantas tramas desea capturar?");
            numTramas = lector.nextInt();

            switch ( opcion ) {
                case 1:
                    switch(opc) {
                        case 1: //Ethernet
                            break;
                            
                        case 2: //LLC
                                
                            break;
                            
                        case 3: //ARP
                            break;
                            
                        case 4: //IP
                            IPTrama ip = new IPTrama();
                                try {
                                    ip.getIP(numTramas);
                                } catch (Exception e) {
                                    System.out.println("Error al analizar ip");
                                }
                            break;

                    }
                break;
                
                case 2: //Capturar desde archivo
                    lector.nextLine();
                    System.out.println("Escriba la ruta absoluta del archivo");
                    FileRoute = lector.nextLine();
                    FileRoute = FileRoute.replace("\\", "/");
                    
                    switch(opc) {
                        case 1: //Ethernet
                            
                            break;
                            
                        case 2: //LLC
                                LLCFile llc = new LLCFile();
                                try {
                                    llc.getLLC_File(numTramas, FileRoute);
                                } catch (Exception e) {
                                    System.out.println("Error al analizar ip");
                                }
                            break;
                            
                        case 3: //ARP
                            
                            break;
                            
                        case 4: //IP
                            
                            break;

                    }
                break;
            }
        } while ( opcion != 0 );
    }


    public static int seleccionarFiltro(){
        int opc = 0;
        Scanner lector = new Scanner(System.in);
        System.out.println("Seleccione el filtro");
        System.out.println("1.- Ethernet");
        System.out.println("2.- LLC");
        System.out.println("3.- ARP");
        System.out.println("4.- IP");
        opc = lector.nextInt();
        return opc;
    }
}