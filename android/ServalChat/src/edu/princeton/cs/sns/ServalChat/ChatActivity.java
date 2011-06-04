/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package edu.princeton.cs.sns.ServalChat;

import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;

import edu.princeton.cs.sns.ServalChat.R;
import serval.net.ServalDatagramSocket;
import serval.net.ServalDatagramPacket;
import serval.net.ServiceID;
import android.app.Activity;
import android.os.Bundle;
import android.text.Editable;
import android.text.method.ScrollingMovementMethod;
import android.util.Log;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

public class ChatActivity extends Activity {
    /** Called when the activity is first created. */
	private TextView chatWindow = null;
	private TextView statusText = null;
	private EditText chatInput = null;
	private Button sendButton = null;
	private Button cancelButton = null;
	private ServalDatagramSocket sock = null;
	private TextReceiver textReceiver = null;
	private Thread textReceiverThread = null;
	
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        
        chatInput = (EditText) findViewById(R.id.chatinput);
        statusText = (TextView) findViewById(R.id.statuslabel);
        chatWindow = (TextView) findViewById(R.id.chatwindow);
        sendButton = (Button) findViewById(R.id.send);
        cancelButton = (Button) findViewById(R.id.cancel);
        
        chatInput.setOnKeyListener(new View.OnKeyListener() {
			public boolean onKey(View v, int keyCode, KeyEvent event) {
				switch (keyCode) {
				case KeyEvent.KEYCODE_ENTER:
					if (chatInput.hasFocus()) {
						sendText();
					}
					return true;
				}
				return false;
			}
        });
        sendButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
            	sendText();
            }
        });
        cancelButton.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
            	cancelSend();
            }
        });
        chatWindow.setMovementMethod(new ScrollingMovementMethod());
    }
    @Override
	protected void onStart() {
		super.onStart();
		Log.d("ServalChat", "onStart");
		
		textReceiver = new TextReceiver();
		textReceiverThread = new Thread(textReceiver);
		textReceiverThread.start();
    }
    
    @Override
	protected void onStop() {
		super.onStop();
		Log.d("ServalChat", "onStop");
		
		if (sock != null) {
			Log.d("ServalChat", "Closing socket");
			sock.close();
		}
		if (textReceiverThread != null) {
			textReceiver.signalExit();
			try {
				textReceiverThread.join();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
    }
    
    @Override
	protected void onDestroy() {
		super.onDestroy();
		Log.d("ServalChat", "onDestroy");
	}
    
    private class TextReceiver implements Runnable {
		private volatile boolean shouldExit = false;
		private ServalDatagramPacket pack = 
            new ServalDatagramPacket(new byte[1024], 1024);
		
		private class ChatWindowUpdater implements Runnable {
			String text;
			
			public ChatWindowUpdater(String text) {
				this.text = text;
			}
			@Override
			public void run() {
				chatWindow.append("Other: " + text + "\n");
			}
		}
		private class StatusUpdater implements Runnable {
			
			String text;
			
			public StatusUpdater(String text) {
				this.text = text;
			}
			@Override
			public void run() {
				statusText.setText(text);
			}
		}

		public synchronized void signalExit() {
			shouldExit = false;
		}
		
		@Override
		public void run() {
			
			Log.d("ServalChat", "Text receiver thread running");

			try {
				sock = new ServalDatagramSocket(new ServiceID((short) 32769));
				sock.setSoTimeout(3000);
				statusText.post(new StatusUpdater("Connecting..."));
				sock.connect(new ServiceID((short) 16385), 10000);
				Log.d("ServalChat", "connected");
				
				statusText.post(new StatusUpdater("Connected"));
			} catch (Exception e) {
				Log.d("ServalChat", "Connection failed: " + e.getMessage());
				statusText.post(new StatusUpdater("Connection failed: " + e.getMessage()));
				if (sock != null) {
					sock.close();
					sock = null;
				}
				return;
			}
			
			while (!shouldExit) {
				try {
					Log.d("ServalChat", "receiving...");
					int len = sock.receive(pack);

					if (len == -1) {
						// Other end closed
						shouldExit = true;
						break;
					}
					String rsp = new String(pack.getData(), 0, pack.getLength());
					Log.d("ServalChat", "response length=" + pack.getLength());
					Log.d("ServalChat", rsp);
					
					chatWindow.post(new ChatWindowUpdater(rsp));
					
				} catch (SocketTimeoutException e) {
					/* SO_RCVTIMEO set, try again. */
					Log.d("ServalChat", "TimeoutException: " + e.getMessage());
				} catch (InterruptedIOException e) {
					Log.d("ServalChat", "InterruptException: " + e.getMessage());
				} catch (Exception e) {
					Log.d("ServalChat", "ERROR - " + e.getMessage());
					break;
				}
			}
		}
    }
    
    private void sendText() {
		Editable ed = chatInput.getText();
		String msg = ed.toString();

		if (msg.length() == 0) {
			return;
		}
        this.chatWindow.append("me: " + msg + "\n");
        
		ed.clear();
		
		if (sock != null && sock.isConnected()) {
			byte[] data = msg.getBytes();
			
			try {
				ServalDatagramPacket pack = 
                    new ServalDatagramPacket(data, data.length);
				sock.send(pack);
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				Log.d("ServalChat", "Error: " + e.getMessage());
				if (sock != null) {
					sock.close();
					sock = null;
				}
				//msg += " - failed!";
			}
		}
    }
    private void cancelSend() {
    	Editable ed = chatInput.getText();
    	ed.clear();
    }
}
