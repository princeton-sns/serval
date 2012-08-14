package org.servalarch.serval;

import android.content.Context;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ToggleButton;

public class ServalFragment extends Fragment {

	private Button addServiceButton, removeServiceButton;
	EditText editServiceText, editIpText;
	ToggleButton servicePerm;
	private View view;
	
	public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
		super.onCreateView(inflater, container, savedInstanceState);
		view = inflater.inflate(R.layout.frag_serval, container, false);
		
		
		editServiceText = (EditText) view.findViewById(R.id.edit_service_field);
		editIpText = (EditText) view.findViewById(R.id.ip_input_field);

		addServiceButton = (Button) view.findViewById(R.id.add_service_button);
		addServiceButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View arg0) {
				AppHostCtrl.performOp(getActivity().getApplicationContext(), editServiceText.getText().toString(), 
						editIpText.getText().toString(), AppHostCtrl.SERVICE_ADD);
			}
		});
		removeServiceButton = (Button) view.findViewById(R.id.remove_service_button);
		removeServiceButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View arg0) {
				AppHostCtrl.performOp(getApplicationContext(), editServiceText.getText().toString(), 
						editIpText.getText().toString(), AppHostCtrl.SERVICE_REMOVE);
			}
		});		
		servicePerm = (ToggleButton) view.findViewById(R.id.servicePerm);
		
		return view;
	}
	
	private Context getApplicationContext() {
		return getActivity().getApplicationContext();
	}
	
}
