package org.servalarch.servalctrl;

public class RemoteHostCtrl extends HostCtrl {
	RemoteHostCtrl(HostCtrlCallbacks cbs) throws HostCtrlException {
		super(HostCtrl.HOSTCTRL_REMOTE, cbs);
	}
}
