/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.serval;

import java.util.ArrayList;

import android.app.Notification;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Intent;
import android.os.Binder;
import android.os.Handler;
import android.os.IBinder;
import android.os.Message;
import android.os.Messenger;
import android.os.RemoteException;
import android.util.Log;

public class TranslatorService extends Service {
	static {
		System.loadLibrary("translator_jni");
	}
	
	/** For showing and hiding our notification. */
	NotificationManager mNM;

	/** Keeps track of all current registered clients. */
	ArrayList<Messenger> mClients = new ArrayList<Messenger>();
	/** Holds last value set by a client. */
	int mValue = 0;
    
	Thread mTranslatorThread = null;
	/**
	 * Command to the service to register a client, receiving callbacks
	 * from the service.  The Message's replyTo field must be a Messenger of
	 * the client where callbacks should be sent.
	 */
	static final int MSG_REGISTER_CLIENT = 1;

	/**
	 * Command to the service to unregister a client, ot stop receiving callbacks
	 * from the service.  The Message's replyTo field must be a Messenger of
	 * the client as previously given with MSG_REGISTER_CLIENT.
	 */
	static final int MSG_UNREGISTER_CLIENT = 2;

	/**
	 * Command to service to set a new value.  This can be sent to the
	 * service to supply a new value, and will be sent by the service to
	 * any registered clients with the new value.
	 */
	static final int MSG_SET_VALUE = 3;

	/**
	 * Handler of incoming messages from clients.
	 */
	class IncomingHandler extends Handler {
		@Override
		public void handleMessage(Message msg) {
			switch (msg.what) {
			case MSG_REGISTER_CLIENT:
				mClients.add(msg.replyTo);
				break;
			case MSG_UNREGISTER_CLIENT:
				mClients.remove(msg.replyTo);
				break;
			case MSG_SET_VALUE:
				mValue = msg.arg1;
				for (int i = mClients.size()-1; i>=0; i--) {
					try {
						mClients.get(i).send(Message.obtain(null,
										    MSG_SET_VALUE, mValue, 0));
					} catch (RemoteException e) {
						// The client is dead.  Remove it from the list;
						// we are going through the list from back to front
						// so this is safe to do inside the loop.
						mClients.remove(i);
					}
				}
				break;
			default:
				super.handleMessage(msg);
			}
		}
	}

	/**
	 * Target we publish for clients to send messages to IncomingHandler.
	 */
	final Messenger mMessenger = new Messenger(new IncomingHandler());

        native int runTranslator(int port, boolean xtranslate);
	public native int shutdown();
	private boolean isRunning = false;
	private int startId = -1;
	
	private class TranslatorRunLoop implements Runnable {
		@Override
		public void run() {
			Log.i("Serval", "Translator running");
			isRunning = true;
			int ret = runTranslator(8080, true);
			Log.i("Serval", "Translator exits with value " + ret);
			isRunning = false;
			stopSelfResult(startId);
		}
	}
	@Override
	public void onCreate() {
		mNM = (NotificationManager)getSystemService(NOTIFICATION_SERVICE);
		
		// Display a notification about us starting.
		showNotification();
	
		if (!isRunning) {
			Log.i("Serval", "Starting Serval translator on port 8080");
			mTranslatorThread = new Thread(new TranslatorRunLoop());
			mTranslatorThread.start();
		}
	}

	@Override
	public void onLowMemory() {
		Log.i("Serval", "Low memory! Shutting down the Serval translator");
		shutdown();
	}

	@Override
	public int onStartCommand(Intent intent, int startFlags, int startId) {
		this.startId = startId;
		return START_STICKY;
	}
	
	@Override
	public void onDestroy() {

		Log.i("Serval", "Stopping Serval translator");
		
		// Cancel the persistent notification.
		mNM.cancel(R.string.translator_service_started);

		// Tell the user we stopped.
		if (isRunning) {
			shutdown();
		}

		try {
			mTranslatorThread.join();
		} catch (InterruptedException e) {
		    
		}
		Log.i("Serval", "Joined with translator main thread");
	}
	
	public class TranslatorBinder extends Binder {
		TranslatorService getTranslator() {
			return TranslatorService.this;
		}
	}
	private final TranslatorBinder mBinder = new TranslatorBinder();
	
	/**
	 * When binding to the service, we return an interface to our messenger
	 * for sending messages to the service.
	 */
	@Override
	public IBinder onBind(Intent intent) {
		//return mMessenger.getBinder();
		return mBinder;
	}

	/**
	 * Show a notification while this service is running.
	 */
	private void showNotification() {
		CharSequence text = getText(R.string.translator_service_started);
		
		// Set the icon, scrolling text and timestamp
		Notification notification = new Notification(android.R.drawable.star_on, text,
							     System.currentTimeMillis());
		
		// The PendingIntent to launch the Serval activity if the
		// user selects this notification
		Intent status = new Intent(this, ServalActivity.class);
		PendingIntent contentIntent = PendingIntent.getActivity(this, 0, status, 0);
		
		// Set the info for the views that show in the
		// notification panel.
		notification.setLatestEventInfo(this, getText(R.string.translator_service_label),
						text, contentIntent);
		notification.flags |= Notification.FLAG_ONGOING_EVENT;
		
		mNM.notify(R.string.translator_service_started, notification);
	}
}
