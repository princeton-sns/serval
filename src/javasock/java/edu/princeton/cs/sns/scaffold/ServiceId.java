package edu.princeton.cs.sns.scaffold;

public class ServiceId {
	private byte[] identifier = null;

	public ServiceId(byte[] id) {
		this.identifier = id;
	}
	public ServiceId(short id) {
		this.identifier = new byte[2];
		this.identifier[0] = (byte)((id >> 8) & 0xff);
		this.identifier[1] = (byte)((id) & 0xff);
	}
	public byte[] getId() {
		return identifier;
	}
	public int getLength() {
		return identifier.length;
	}
}
