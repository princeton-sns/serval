/* -*- Mode: Java; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
package org.servalarch.serval;

import android.content.Context;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.ToggleButton;

public class ServalFragment extends Fragment {

	private Button addServiceButton, removeServiceButton;
	EditText editServiceText, editIpText;
	ToggleButton servicePerm, autoMigrationButton;
	private View view;
	private Spinner spinner;

	public View onCreateView(LayoutInflater inflater, ViewGroup container,
			Bundle savedInstanceState) {
		super.onCreateView(inflater, container, savedInstanceState);
		view = inflater.inflate(R.layout.frag_serval, container, false);

		spinner = (Spinner) view.findViewById(R.id.rule_type_spinner);
		ArrayAdapter<CharSequence> adapter = ArrayAdapter.createFromResource(
				view.getContext(), R.array.service_rule_types,
				android.R.layout.simple_spinner_item);
		adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
		spinner.setAdapter(adapter);
		spinner.setOnItemSelectedListener(new OnItemSelectedListener() {

			@Override
			public void onItemSelected(AdapterView<?> arg0, View view,
					int i, long l) {
				if (i == 0) {
					editIpText.setEnabled(true);
				} else {
					editIpText.setEnabled(false);
				}
			}

			@Override
			public void onNothingSelected(AdapterView<?> arg0) {
				// TODO Auto-generated method stub
				
			}
			
		});

		editServiceText = (EditText) view.findViewById(R.id.edit_service_field);
		editIpText = (EditText) view.findViewById(R.id.ip_input_field);

		addServiceButton = (Button) view.findViewById(R.id.add_service_button);
		addServiceButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View arg0) {
				AppHostCtrl.performOp(getActivity().getApplicationContext(),
						editServiceText.getText().toString(), 
						getServiceRuleArgument(), 
						AppHostCtrl.SERVICE_ADD);
			}
		});
		removeServiceButton = (Button) view
				.findViewById(R.id.remove_service_button);
		removeServiceButton.setOnClickListener(new OnClickListener() {
			@Override
			public void onClick(View arg0) {
				AppHostCtrl.performOp(getApplicationContext(), 
						editServiceText.getText().toString(), 
						getServiceRuleArgument(),
						AppHostCtrl.SERVICE_REMOVE);
			}
		});
		servicePerm = (ToggleButton) view.findViewById(R.id.servicePerm);
		this.autoMigrationButton = (ToggleButton) view.findViewById(R.id.toggle_auto_migration);
		this.autoMigrationButton
		.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
			@Override
			public void onCheckedChanged(CompoundButton buttonView,
					boolean isChecked) {
				String cmd = "echo " + (isChecked ? "1" : "0") + " >/proc/sys/net/serval/auto_migrate";
				((ServalActivity) getActivity()).executeSuCommand(cmd, false);
			}
		});
		this.autoMigrationButton.setChecked(ServalActivity.readBooleanProcEntry("/proc/sys/net/serval/auto_migrate"));
		
		return view;
	}

	private String getServiceRuleArgument() {
		int i = spinner.getSelectedItemPosition();
		
		if (i == 1)
			return "delay";
		else if (i == 2)
			return "drop";
		
		return editIpText.getText().toString();
	}
	
	private Context getApplicationContext() {
		return getActivity().getApplicationContext();
	}

}
