package org.servalarch.serval;

import android.app.Activity;
import android.app.ActivityManager;
import android.app.ActivityManager.RunningServiceInfo;
import android.content.Intent;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.CompoundButton;
import android.widget.ToggleButton;

public class TranslatorFragment extends Fragment {

	private static final String[] ADD_HTTP_RULES = {
		"ifconfig dummy0 192.168.25.25 -arp",
		"ip rule add to 128.112.7.54 table main priority 10", // TODO this change based on the proxy IP
		"ip rule add from 192.168.25.0/24 table main priority 20",
		"ip rule add from all table 1 priority 30",
		"ip route add default via 192.168.25.25 dev dummy0 table 1",
		"echo 1 > /proc/sys/net/ipv4/ip_forward",
		"echo 1024 > /proc/sys/net/ipv4/neigh/default/gc_thresh1",
		"echo 2048 > /proc/sys/net/ipv4/neigh/default/gc_thresh2",
		"echo 4096 > /proc/sys/net/ipv4/neigh/default/gc_thresh3",
		"iptables -t nat -A OUTPUT -p tcp --dport 80 -m tcp --syn -j REDIRECT --to-ports 8080",
		"iptables -t nat -A OUTPUT -p tcp --dport 443 -m tcp --syn -j REDIRECT --to-ports 8080",
		"iptables -t nat -A OUTPUT -p tcp --dport 5001 -m tcp --syn -j REDIRECT --to-ports 8080",
		"iptables -A FORWARD -s 192.168.25.0/255.255.255.0 -p tcp --dport 80 -j DROP",
		"iptables -A FORWARD -s 192.168.25.0/255.255.255.0 -p tcp --dport 443 -j DROP",
		"iptables -A FORWARD -s 192.168.25.0/255.255.255.0 -p tcp --dport 5001 -j DROP",
		"iptables -A FORWARD -s 192.168.25.0/255.255.255.0 -j ACCEPT",
		"iptables -t nat -A POSTROUTING ! -o dummy0 -j MASQUERADE"
	};
	
	private static final String[] ADD_ALL_RULES = {
		"iptables -t nat -A OUTPUT -p tcp -m tcp --syn -j REDIRECT --to-ports 8080"
	};
	
	private static final String[] DEL_HTTP_RULES = {
		"ifconfig dummy0 down",
		"ip rule del to 128.112.7.54 table main priority 10", // TODO this change based on the proxy IP
		"ip rule del from 192.168.25.0/24 table main priority 20",
		"ip rule del from all table 1 priority 30",
		"ip route del default via 192.168.25.25 dev dummy0 table 1",
		"echo 0 > /proc/sys/net/ipv4/ip_forward",
		"iptables -t nat -D OUTPUT -p tcp --dport 80 -m tcp --syn -j REDIRECT --to-ports 8080",
		"iptables -t nat -D OUTPUT -p tcp --dport 443 -m tcp --syn -j REDIRECT --to-ports 8080",
		"iptables -t nat -D OUTPUT -p tcp --dport 5001 -m tcp --syn -j REDIRECT --to-ports 8080",
		"iptables -D FORWARD -s 192.168.25.0/255.255.255.0 -p tcp --dport 80 -j DROP",
		"iptables -D FORWARD -s 192.168.25.0/255.255.255.0 -p tcp --dport 443 -j DROP",
		"iptables -D FORWARD -s 192.168.25.0/255.255.255.0 -p tcp --dport 5001 -j DROP",
		"iptables -D FORWARD -s 192.168.25.0/255.255.255.0 -j ACCEPT",
		"iptables -t nat -D POSTROUTING ! -o dummy0 -j MASQUERADE"
	};
	
	private static final String[] DEL_ALL_RULES = {
		"iptables -t nat -D OUTPUT -p tcp -m tcp --syn -j REDIRECT --to-ports 8080"
	};
	
	private ToggleButton translatorButton, transHttpButton, transAllButton;
	
	private View view;
	
	public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
		super.onCreateView(inflater, container, savedInstanceState);
		view = inflater.inflate(R.layout.frag_translator, container, false);

		this.translatorButton = (ToggleButton) view.findViewById(R.id.translatorToggle);
		this.translatorButton.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
			@Override
			public void onCheckedChanged(CompoundButton buttonView,
					boolean isChecked) {
				if (isChecked) {
					getActivity().startService(new Intent(getActivity(), TranslatorService.class));
					if (transAllButton.isChecked())
						executeRules(ADD_ALL_RULES);
					else if (transHttpButton.isChecked())
						executeRules(ADD_HTTP_RULES);
				} else {
					getActivity().stopService(new Intent(getActivity(), TranslatorService.class));
					if (transAllButton.isChecked())
						executeRules(DEL_ALL_RULES);
					else if (transHttpButton.isChecked())
						executeRules(DEL_HTTP_RULES);
				}
			}
		});
		
		this.transHttpButton = (ToggleButton) view.findViewById(R.id.toggle_trans_http);
		this.transHttpButton.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
			
			@Override
			public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
				if (isChecked) {
					if (isTranslatorRunning() && !transAllButton.isChecked()) {
						executeRules(ADD_HTTP_RULES);
					}
				}
				else {
					if (isTranslatorRunning() && !transAllButton.isChecked()) {
						executeRules(DEL_HTTP_RULES);
					}
				}
			}
		});
		
		this.transAllButton = (ToggleButton) view.findViewById(R.id.toggle_trans_all);
		this.transAllButton.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
			
			@Override
			public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
				if (isChecked) {
					if (isTranslatorRunning()) { 
						if (transHttpButton.isChecked()) {
							executeRules(DEL_HTTP_RULES);
						}
						executeRules(ADD_ALL_RULES);
					}
					
				}
				else {
					if (isTranslatorRunning()) {
						executeRules(DEL_ALL_RULES);
						if (transHttpButton.isChecked()) {
							executeRules(ADD_HTTP_RULES);
						}
					}
				}
			}
		});
		
		if (isTranslatorRunning())
			translatorButton.setChecked(true);
		else
			translatorButton.setChecked(false);
		
		return view;
	}
	
	private void executeRules(String[] rules) {
		for (String rule : rules) {
			executeSuCommand(rule);
		}

	}
	
	private boolean executeSuCommand(String cmd) {
		return ((ServalActivity) getActivity()).executeSuCommand(cmd);
	}
	
	private boolean isTranslatorRunning() {
	    ActivityManager manager = (ActivityManager) getActivity().getSystemService(Activity.ACTIVITY_SERVICE);
	    for (RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
	        if ("org.servalarch.serval.TranslatorService".equals(service.service.getClassName())) {
	            return true;
	        }
	    }
	    return false;
	}
}
