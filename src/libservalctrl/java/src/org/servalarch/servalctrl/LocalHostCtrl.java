package org.servalarch.servalctrl;

public class LocalHostCtrl extends HostCtrl {
	public LocalHostCtrl(HostCtrlCallbacks cbs) throws HostCtrlException {
		super(HostCtrl.HOSTCTRL_LOCAL, cbs);
	}
}
