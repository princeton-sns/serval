/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.test;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.lang.System;
import java.lang.Thread;
import java.lang.Runnable;

import org.servalarch.net.ServalSocket;
import org.servalarch.net.ServiceID;

public class TCPClient {
    private ServalSocket sock;
    private BufferedReader in;
    private BufferedWriter out;

    public TCPClient() {

    }

    private class CloseThread implements Runnable {
        public CloseThread() {
        }
        public void run() {
            //System.out.println("CloseThread running\n");
            try {
                Thread.sleep(4000);
            } catch (InterruptedException e) {

            }
            
            System.out.println("Closing socket\n");
            try {
				sock.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
            System.out.println("Socket closed\n");
        }
    }
    
    private int sendMessage(String msg) {
		if (msg.length() == 0) {
			return 0;
		}

		if (sock != null) {
			
			try {
				out.write(msg);
                out.newLine();
                out.flush();
				String rsp = in.readLine();
				System.out.println("Response: " + rsp);
			} catch (IOException e) {
                System.err.println("Error: " + e.getMessage());
				//msg += " - failed!";
                return -1;
			}
		}
		return msg.length();
    }
    private void run() {
        try {
        	//ServiceID localServiceID = new ServiceID((short) 32769)
            sock = new ServalSocket(new ServiceID(16385));
            //sock.setSoTimeout(5000);
            //sock.connect(new ServiceID((short) 16385), 4000);
        } catch (Exception e) {
            System.err.println("connect failure: " + e.getMessage());
            
            if (sock != null) {
				try {
					sock.close();
				} catch (IOException e1) {
					e1.printStackTrace();
				}
            }
            
            return;
        }

        System.out.println("Connected!");

		(new Thread(new CloseThread())).start();

        try {
			out =  new BufferedWriter(new OutputStreamWriter(sock.getOutputStream()));
		} catch (IOException e) {
			System.err.println("Could not open output stream");
			try {
				in.close();
				sock.close();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
			return;
		}

        try {
            in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
		} catch (IOException e) {
			System.err.println("Could not open input stream");
			try {
				sock.close();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
			return;
		}
        
        String msg = "Hello World!";
       
        System.out.println("Sending: " + msg);

		sendMessage(msg);

		try {
			in.close();
			out.close();
			sock.close();
		} catch (IOException e) {
			//e.printStackTrace();
		}
	}

	public static void main(String args[]) {
		System.out.println("TCPClient starting");
		TCPClient c = new TCPClient();

        c.run();
    }
}
