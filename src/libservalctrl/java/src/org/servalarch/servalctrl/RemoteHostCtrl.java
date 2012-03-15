package org.servalarch.servalctrl;

public class RemoteHostCtrl extends HostCtrl {
	public RemoteHostCtrl(HostCtrlCallbacks cbs) throws HostCtrlException {
		super(HostCtrl.HOSTCTRL_REMOTE, cbs);
	}
}
