/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package serval.test;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.System;
import java.lang.Thread;
import java.lang.Runnable;
import serval.net.*;

public class TCPClient {
    private ServalSocket sock;
    private ObjectOutputStream out;
    private ObjectInputStream in;
    
    public TCPClient() {

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
				out.writeUTF(msg);
				// FIXME: Should not do a blocking receive in this function

                System.out.println("Receiving...");
				String rsp = in.readUTF();
				System.out.println("Response: " + rsp);
			} catch (IOException e) {
                System.out.println("Error: " + e.getMessage());
				//msg += " - failed!";
                return -1;
			}
		}
		return msg.length();
    }
    private void run() {
        try {
        	//ServiceID localServiceID = new ServiceID((short) 32769)
            sock = new ServalSocket(new ServiceID((short) 16385));
            sock.setSoTimeout(5000);
            //sock.connect(new ServiceID((short) 16385), 4000);
        } catch (Exception e) {
            System.out.println("failure: " + e.getMessage());
            
            if (sock != null) {
				try {
					sock.close();
				} catch (IOException e1) {
					e1.printStackTrace();
				}
            }
            
            return;
        }

        try {
			in = new ObjectInputStream(sock.getInputStream());
		} catch (IOException e) {
			System.err.println("Could not open input stream");
			try {
				sock.close();
			} catch (IOException e1) {
				e1.printStackTrace();
			}
			return;
		}
        try {
			out = new ObjectOutputStream(sock.getOutputStream());
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

        String msg = "Hello World!";

        System.out.println("Sending: " + msg);

		(new Thread(new CloseThread())).start();

		sendMessage(msg);

		try {
			in.close();
			out.close();
			sock.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public static void main(String args[]) {
		System.out.println("TCPClient starting");
		TCPClient c = new TCPClient();

        c.run();
    }
}
