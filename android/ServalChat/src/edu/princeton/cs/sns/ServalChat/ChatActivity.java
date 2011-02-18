/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package edu.princeton.cs.sns.ServalChat;

import java.io.IOException;
import java.net.SocketException;
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
		
		try {
			sock = new ServalDatagramSocket(new ServiceID((short) 32769));
			sock.connect(new ServiceID((short) 16385));
			Log.d("ServalChat", "connected");
			statusText.setText("Connected");
		} catch (SocketException e) {
			Log.d("ServalChat", "Error: " + e.getMessage());
			sock = null;
		}
    }
    @Override
	protected void onStop() {
		super.onStop();
		Log.d("ServalChat", "onStop");
		if (sock != null)
			sock.close();
    }
    @Override
	protected void onDestroy() {
		super.onDestroy();
		Log.d("ServalChat", "onDestroy");
	}
    private void sendText() {
		Editable ed = chatInput.getText();
		String msg = ed.toString();

		if (msg.length() == 0) {
			return;
		}
        this.chatWindow.append("me: " + msg + "\n");
        
		ed.clear();
		
		if (sock != null) {
			byte[] data = msg.getBytes();
			
			try {
				ServalDatagramPacket pack = 
                    new ServalDatagramPacket(data, data.length);
				sock.send(pack);
				// FIXME: Should not do a blocking receive in this function
				sock.receive(pack);

				String rsp = new String(pack.getData(), 0, pack.getLength());
				Log.d("ServalChat", "response length=" + pack.getLength());
				Log.d("ServalChat", rsp);
				chatWindow.append("Other: " + rsp + "\n");
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
