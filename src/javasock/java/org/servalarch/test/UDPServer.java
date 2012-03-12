/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.test;

import java.net.SocketTimeoutException;
import java.lang.System;
import java.lang.Thread;
import java.lang.Runnable;

import org.servalarch.net.ServalDatagramPacket;
import org.servalarch.net.ServalDatagramSocket;
import org.servalarch.net.ServalServerDatagramSocket;
import org.servalarch.net.ServiceID;


public class UDPServer {
	private ServalServerDatagramSocket serverSock;
	private int num = 0;

	public UDPServer() {
		
	}
	
	private class Client implements Runnable {
        ServalDatagramSocket sock;
        int id;
        
        ServalDatagramPacket pack = 
            new ServalDatagramPacket(new byte[1024], 1024);

        public Client(ServalDatagramSocket sock, int num) {
            this.sock = sock;
            this.id = num;
        }
        
        public void run() {
            System.out.println("Client " + id + " running...");
            //sock.setSoTimeout(3000);
            while (true) {
                try {
                    int len = sock.receive(pack);

                    if (len == -1) {
                        System.out.printf("Client %d other end closed\n", id);
                        break;
                    }
                    
                    String msg = new String(pack.getData(), 
                                            0, pack.getLength());
                    
                    System.out.printf("Client %d received \'%s\'\n",
                                      id, msg);
                    msg = msg.toUpperCase();
                    byte[] b = msg.getBytes("UTF-8");
                    ServalDatagramPacket rsp = 
                        new ServalDatagramPacket(b, b.length); 
                    sock.send(rsp);

                    System.out.printf("Client %d sent \'%s\'\n",
                                      id, msg);
                } catch (SocketTimeoutException e) {
                    // Receive timeout, if set via setSoTimeout().
                    
                } catch (Exception e) {
                    System.err.println("Socket error: " + e.getMessage());
                    break;
                }
            }           
            sock.close();
            System.out.println("Client " + id + " exits...\n");
        }             
	}

    public void run() {
	    try {
		    serverSock = 
                new ServalServerDatagramSocket(new ServiceID(16385));
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            return;
        }

        System.out.println("UDP server listening...");
        
        while (true) {
            try {
                (new Thread(new Client(serverSock.accept(), ++num))).start();
                System.out.println("accepted client " + num);
            } catch (Exception e) {
                System.err.println("ERROR: " + e.getMessage());
                break;
            }
        }
    }
    
    public static void main(String args[]) {
        System.out.println("UDPServer starting");
        UDPServer s = new UDPServer();

        s.run();
    }
}
