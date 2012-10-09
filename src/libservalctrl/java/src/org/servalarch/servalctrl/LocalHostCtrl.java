/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.servalctrl;

public class LocalHostCtrl extends HostCtrl {
	public LocalHostCtrl(HostCtrlCallbacks cbs) throws HostCtrlException {
		super(HostCtrl.HOSTCTRL_LOCAL, cbs);
	}
}
