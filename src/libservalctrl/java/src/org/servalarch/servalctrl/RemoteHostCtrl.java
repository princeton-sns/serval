/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.servalctrl;

public class RemoteHostCtrl extends HostCtrl {
	public RemoteHostCtrl(HostCtrlCallbacks cbs) throws HostCtrlException {
		super(HostCtrl.HOSTCTRL_REMOTE, cbs);
	}
}
