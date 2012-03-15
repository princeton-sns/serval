/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.test;

import java.net.SocketTimeoutException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.lang.System;
import java.lang.Thread;
import java.lang.Runnable;

import org.servalarch.net.ServalServerSocket;
import org.servalarch.net.ServalSocket;
import org.servalarch.net.ServiceID;

public class TCPServer {
	private ServalServerSocket serverSock;
	private int num = 0;

	public TCPServer() {
		
	}
	
	private class Client implements Runnable {
        ServalSocket sock;
        int id;

        public Client(ServalSocket sock, int num) {
            this.sock = sock;
            this.id = num;
        }
        
        public void run() {
            System.out.println("Client " + id + " running...");
            //sock.setSoTimeout(3000);
            BufferedReader in;
            BufferedWriter out;

			try {
				in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			} catch (IOException e) {
				System.out.println("Could not open input stream");
				return;
			}
			            
			try {
				out = new BufferedWriter(new OutputStreamWriter(sock.getOutputStream()));
			} catch (IOException e) {
				System.out.println("Could not open output stream");
				return;
			}

            while (true) {
                try {
                    System.out.println("Waiting for client message");

                    String msg = in.readLine();

                    if (msg == null) {
                        System.out.printf("Client %d closed\n", id);
                        break;
                    }

                    System.out.printf("Client %d received \'%s\'\n",
                                      id, msg);
                    
                    out.write(msg.toUpperCase());
                    out.newLine();
                    out.flush();

                    System.out.printf("Client %d sent \'%s\'\n",
                                      id, msg);
                } catch (SocketTimeoutException e) {
                    // Receive timeout, if set via setSoTimeout().
                    
                } catch (Exception e) {
                    System.err.println("Socket error: " + e.getMessage());
                    break;
                }
            }    
            try {
				in.close();
	            out.close();
	            sock.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
            System.out.println("Client " + id + " exits...\n");
        }             
	}

    public void run() {
	    try {
		    serverSock = 
                new ServalServerSocket(new ServiceID(16385));
        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
            return;
        }

        System.out.println("TCP server listening...");
        
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
        System.out.println("TCPServer starting");
        TCPServer s = new TCPServer();

        s.run();
    }
}
