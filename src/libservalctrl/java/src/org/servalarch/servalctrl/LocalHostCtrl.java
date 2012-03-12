package org.servalarch.servalctrl;

public class LocalHostCtrl extends HostCtrl {
	LocalHostCtrl(HostCtrlCallbacks cbs) throws HostCtrlException {
		super(HostCtrl.HOSTCTRL_LOCAL, cbs);
	}
}
