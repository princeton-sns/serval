/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package serval.test;

import serval.net.*;
import java.lang.System;

public class UDPClient {
    private ServalDatagramSocket sock;

    
    public UDPClient() {

    }
    private void run() {
        try {
            sock = new ServalDatagramSocket();
            sock.bind(new ServalSocketAddress(new ServiceId((short) 32769)));
            sock.connect(new ServalSocketAddress(new ServiceId((short) 16385)));
        } catch (Exception e) {
            System.out.println("connect failure: " + e.getMessage());
        }
        while (true) {
            break;
        }
        sock.close();
    }
    public static void main(String args[]) {
        System.out.println("UDPClient starting");
    }
}
