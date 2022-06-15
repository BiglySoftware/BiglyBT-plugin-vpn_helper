/*
 * Copyright (C) Azureus Software, Inc, All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details ( see the LICENSE file ).
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package com.vuze.plugin.azVPN_Helper;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import com.biglybt.core.util.Constants;
import com.biglybt.core.util.FileUtil;
import com.biglybt.core.util.SystemProperties;
import com.biglybt.util.JSONUtils;
import com.biglybt.util.MapUtils;
import com.vuze.plugin.azVPN_Helper.CheckerCommon.Status;
import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.ui.config.Parameter;
import com.biglybt.pif.ui.config.StringParameter;
import com.biglybt.pif.ui.model.BasicPluginConfigModel;


public class
Checker_PureVPN
	extends CheckerCommon
{
	private static final String CONFIG_PUREVPN_NETWORK_INTERFACE = "purevpn.network.interface";

	public Checker_PureVPN(PluginInterface pi) {
		super(pi);
	}

	public static List<Parameter> 
	setupConfigModel(
		PluginInterface 		pi,
		BasicPluginConfigModel 	configModel) 
	{
		List<Parameter> params = new ArrayList<>(1);
		
		StringParameter paramAccount = configModel.addStringParameter2(
				CONFIG_PUREVPN_NETWORK_INTERFACE, CONFIG_PUREVPN_NETWORK_INTERFACE, "" );
		
		params.add(paramAccount);

		return params;
	}

	@Override
	protected Status 
	callRPCforPort(
		InetAddress 		vpnIP, 
		StringBuilder 		sReply)
	{
		return( new Status(STATUS_ID_OK));
	}
	
	@Override
	protected boolean 
	canReach(
		InetAddress addressToReach)
	{
		try{
			URI canReachURL = new URI("https://www.purevpn.com/");
			
			return( canReach( addressToReach, canReachURL ));
			
		}catch( URISyntaxException e ){
			
			return( false );
		}
	}
}
