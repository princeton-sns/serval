/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.test;

import java.io.IOException;
import java.lang.System;
import java.lang.Thread;
import java.lang.Runnable;

import org.servalarch.net.ServalDatagramPacket;
import org.servalarch.net.ServalDatagramSocket;
import org.servalarch.net.ServiceID;


public class UDPClient {
    private ServalDatagramSocket sock;
    
    public UDPClient() {

    }

    private class CloseThread implements Runnable {
        public CloseThread() {
        }
        public void run() {
            System.out.println("CloseThread running\n");
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {

            }
            
            System.out.println("Closing socket\n");
            sock.close();
            System.out.println("Socket closed\n");
        }
    }
    private void sendMessage(String msg) {
		if (msg.length() == 0) {
			return;
		}

		if (sock != null) {
			byte[] data = msg.getBytes();
			
			try {
				ServalDatagramPacket pack = 
                    new ServalDatagramPacket(data, data.length);
				sock.send(pack);
				// FIXME: Should not do a blocking receive in this function

                System.out.println("Receiving...");
				sock.receive(pack);
                System.out.println("Receive returned");
				String rsp = new String(pack.getData(), 0, pack.getLength());
				//System.out.println("response length=" + pack.getLength());
				System.out.println("Response: " + rsp);
			} catch (IOException e) {
                System.out.println("Error: " + e.getMessage());
				if (sock != null) {
					sock.close();
					sock = null;
				}
				//msg += " - failed!";
			}
		}
    }
    private void run() {
        try {
            sock = new ServalDatagramSocket(new ServiceID(32769));
            sock.setSoTimeout(5000);
            sock.connect(new ServiceID(16385), 4000);
        } catch (Exception e) {
            System.out.println("failure: " + e.getMessage());
            
            if (sock != null)
                sock.close();
            
            return;
        }

        String msg = "Hello World!";

        System.out.println("Sending: " + msg);
 
        (new Thread(new CloseThread())).start();

        sendMessage(msg);

        if (sock != null)
            sock.close();
    }
    public static void main(String args[]) {
        System.out.println("UDPClient starting");
        UDPClient c = new UDPClient();

        c.run();
    }
}
