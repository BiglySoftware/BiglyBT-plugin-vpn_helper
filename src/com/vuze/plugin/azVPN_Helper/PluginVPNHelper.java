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

import java.lang.reflect.Method;
import java.util.*;

import com.biglybt.core.config.COConfigurationManager;
import com.biglybt.core.util.AERunnable;
import com.biglybt.ui.swt.pif.UISWTInstance;

import com.biglybt.pif.PluginException;
import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.PluginListener;
import com.biglybt.pif.UnloadablePlugin;
import com.biglybt.pif.config.ConfigParameter;
import com.biglybt.pif.config.ConfigParameterListener;
import com.biglybt.pif.logging.LoggerChannel;
import com.biglybt.pif.ui.UIInstance;
import com.biglybt.pif.ui.UIManager;
import com.biglybt.pif.ui.UIManagerListener;
import com.biglybt.pif.ui.config.*;
import com.biglybt.pif.ui.model.BasicPluginConfigModel;
import com.biglybt.pif.ui.model.BasicPluginViewModel;
import com.biglybt.pif.utils.LocaleUtilities;

public class PluginVPNHelper
	implements UnloadablePlugin, UIManagerListener, PluginListener
{
	private static final boolean LOG_TO_STDOUT = false;

	private static final int DEFAULT_CHECK_EVERY_MINS = 2;

	private static final String DEFAULT_VPN_IP_REGEX = "10\\.[0-9]+\\.[0-9]+\\.[0-9]+";

	private static String[] vpnIDs = new String[] {
		"AirVPN",
		"PIA",
		"Mullvad",
		""
	};

	private PluginInterface pi;

	private static LoggerChannel logger;

	protected UIInstance uiInstance;

	public static PluginVPNHelper instance;

	public CheckerCommon checker;

	public String checkerID;

	private BasicPluginConfigModel configModel;

	private BasicPluginViewModel model;

	private UI ui;

	private static long initializedOn;

	private StringListParameter currentVPN;

	protected List<CheckerListener> listeners = new ArrayList<CheckerListener>(1);

	private HashMap<String, List<Parameter>> mapVPNConfigParams;

	private ParameterTabFolder tabFolder;

	/* (non-Javadoc)
	 * @see com.biglybt.pif.Plugin#initialize(com.biglybt.pif.PluginInterface)
	 */
	@Override
	public void initialize(PluginInterface plugin_interface)
			throws PluginException {
		instance = this;

		initializedOn = System.currentTimeMillis();

		this.pi = plugin_interface;

		UIManager uiManager = pi.getUIManager();

		logger = pi.getLogger().getTimeStampedChannel(
				PluginConstants.CONFIG_SECTION_ID);

		model = uiManager.createLoggingViewModel(logger, true);
		model.setConfigSectionID(PluginConstants.CONFIG_SECTION_ID);

		setupConfigModel(uiManager);

		LocaleUtilities i18n = pi.getUtilities().getLocaleUtilities();

		final String currentVpnID = currentVPN.getValue();
		if (currentVpnID.length() > 0) {
			Arrays.sort(vpnIDs, new Comparator<String>() {
				@Override
				public int compare(String o1, String o2) {
					if (o1.equals(o2)) {
						return 0;
					}
					if (o1.equals(currentVpnID)) {
						return -1;
					}
					if (o2.equals(currentVpnID)) {
						return 1;
					}
					return o1.compareTo(o2);
				}
			});
		}

		String[] longNames = new String[vpnIDs.length];
		System.arraycopy(vpnIDs, 0, longNames, 0, longNames.length);

		for (int i = 0; i < vpnIDs.length; i++) {
			String vpnID = vpnIDs[i];
			if (vpnID.length() == 0) {
				continue;
			}

			try {
				i18n.integrateLocalisedMessageBundle(
						"com.vuze.plugin.azVPN_Helper.internat." + vpnID + "_Messages");

				Class<?> checkerCla = Class.forName(
						"com.vuze.plugin.azVPN_Helper.Checker_" + vpnID);

				Method method = checkerCla.getMethod("setupConfigModel",
						PluginInterface.class, BasicPluginConfigModel.class);

				@SuppressWarnings("unchecked")
				List<Parameter> listParams = (List<Parameter>) method.invoke(null, pi,
						configModel);

				boolean visible = vpnID.equals(checkerID);
				if (listParams != null && listParams.size() > 0) {
					ActionParameter paramReset = configModel.addActionParameter2(null,
							"vpnhelper.config.reset.one");
					paramReset.addListener(param -> {
						for (Parameter configParameter : listParams) {
							String name = configParameter.getConfigKeyName();
							if (name != null && name.length() > 0) {
								COConfigurationManager.removeParameter(name);
							}
						}
					});
					listParams.add(paramReset);

					String idLongName = "vpnhelper.name." + vpnID.toLowerCase();
					String groupName;
					boolean hasLongName = i18n.hasLocalisedMessageText(idLongName);
					if (hasLongName) {
						longNames[i] = i18n.getLocalisedMessageText(idLongName);
						groupName = "!" + longNames[i] + "!";
					} else {
						groupName = "!" + vpnID + "!";
					}

					ParameterGroup group = configModel.createGroup(groupName,
							listParams.toArray(new Parameter[0]));
					tabFolder.addTab(group);

					for (Parameter configParameter : listParams) {
						//configParameter.setVisible(visible);
						configParameter.setEnabled(visible);
					}

				}

				mapVPNConfigParams.put(vpnID, listParams);

			} catch (Throwable e) {
				e.printStackTrace();
			}
		}
		currentVPN.setLabels(longNames);

		i18n.integrateLocalisedMessageBundle(
				"com.vuze.plugin.azVPN_Helper.internat.Messages");

		String vpnID = currentVPN.getValue();
		if (vpnID.length() > 0) {
			i18n.integrateLocalisedMessageBundle(
					"com.vuze.plugin.azVPN_Helper.internat." + vpnID + "_Messages");

			try {
				Class<?> checkerCla = Class.forName(
						"com.vuze.plugin.azVPN_Helper.Checker_" + vpnID);

				checker = (CheckerCommon) checkerCla.getConstructor(
						PluginInterface.class).newInstance(pi);
				checkerID = vpnID;

				CheckerListener[] triggers = getCheckerListeners();
				for (CheckerListener l : triggers) {
					try {
						l.checkerChanged(checker);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}

			} catch (Throwable e) {
				e.printStackTrace();
			}

			List<Parameter> list = mapVPNConfigParams.get(vpnID);
			if (list != null && list.size() > 0) {
				for (Parameter configParameter : list) {
					//configParameter.setVisible(true);
					configParameter.setEnabled(true);
				}
			}
		}

		pi.getUIManager().addUIListener(this);

		pi.addListener(this);
	}

	private void setupConfigModel(UIManager uiManager) {
		configModel = uiManager.createBasicPluginConfigModel(
				PluginConstants.CONFIG_SECTION_ID);

		currentVPN = configModel.addStringListParameter2(
				PluginConstants.CONFIG_CURRENT_VPN, "vpnhelper.currentvpn", vpnIDs,
				vpnIDs, "");
		currentVPN.addConfigParameterListener(new ConfigParameterListener() {
			@Override
			public void configParameterChanged(ConfigParameter param) {
				LocaleUtilities i18n = pi.getUtilities().getLocaleUtilities();
				i18n.integrateLocalisedMessageBundle(
						"com.vuze.plugin.azVPN_Helper.internat.Messages");

				if (checker != null) {
					checker.destroy();
					checker = null;

					List<Parameter> list = mapVPNConfigParams.get(checkerID);
					if (list != null && list.size() > 0) {
						for (Parameter configParameter : list) {
							//configParameter.setVisible(false);
							configParameter.setEnabled(false);
						}
					}

					checkerID = null;
				}

				String vpnID = currentVPN.getValue();
				if (vpnID.length() > 0) {
					i18n.integrateLocalisedMessageBundle(
							"com.vuze.plugin.azVPN_Helper.internat." + vpnID + "_Messages");

					try {
						Class<?> checkerCla = Class.forName(
								"com.vuze.plugin.azVPN_Helper.Checker_" + vpnID);

						checker = (CheckerCommon) checkerCla.getConstructor(
								PluginInterface.class).newInstance(pi);
						checkerID = vpnID;

						List<Parameter> list = mapVPNConfigParams.get(vpnID);
						if (list != null && list.size() > 0) {
							for (Parameter configParameter : list) {
								//configParameter.setVisible(true);
								configParameter.setEnabled(true);
							}
						}

					} catch (Throwable e) {
						e.printStackTrace();
					}
				}
				CheckerListener[] triggers = getCheckerListeners();
				for (CheckerListener l : triggers) {
					try {
						l.checkerChanged(checker);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}

				if (checker != null) {
					checker.buildTimer();
					pi.getUtilities().createThread("FirstVPNCheck", new AERunnable() {
						@Override
						public void runSupport() {
							if (checker != null) {
								checker.portBindingCheck();
							}
						}
					});
				}
			}
		});

		IntParameter checkMinsParameter = configModel.addIntParameter2(
				PluginConstants.CONFIG_CHECK_MINUTES, "vpnhelper.check.port.every.mins",
				DEFAULT_CHECK_EVERY_MINS, 0, 60 * 24);
		checkMinsParameter.addListener(new ParameterListener() {
			@Override
			public void parameterChanged(Parameter param) {
				if (checker != null) {
					checker.buildTimer();
				}
			}
		});

		BooleanParameter paramDoPortForwarding = configModel.addBooleanParameter2(
				PluginConstants.CONFIG_DO_PORT_FORWARDING,
				PluginConstants.CONFIG_DO_PORT_FORWARDING, true);

		StringParameter paramRegex = configModel.addStringParameter2(
				PluginConstants.CONFIG_VPN_IP_MATCHING,
				PluginConstants.CONFIG_VPN_IP_MATCHING, DEFAULT_VPN_IP_REGEX);
		paramRegex.setMinimumRequiredUserMode(StringParameter.MODE_ADVANCED);

		StringParameter paramIgnoreAddress = configModel.addStringParameter2(
				PluginConstants.CONFIG_IGNORE_ADDRESS,
				PluginConstants.CONFIG_IGNORE_ADDRESS, "");
		paramIgnoreAddress.setMinimumRequiredUserMode(
				StringParameter.MODE_ADVANCED);

		mapVPNConfigParams = new HashMap<String, List<Parameter>>(1);

		DirectoryParameter paramPortReadLocation = configModel.addDirectoryParameter2(
				PluginConstants.CONFIG_PORT_READ_LOCATION,
				PluginConstants.CONFIG_PORT_READ_LOCATION, "");
		paramPortReadLocation.setMinimumRequiredUserMode(
				StringParameter.MODE_INTERMEDIATE);
		paramDoPortForwarding.addEnabledOnSelection(paramPortReadLocation);

		StringParameter paramPortReadLocationRegEx = configModel.addStringParameter2(
				PluginConstants.CONFIG_PORT_READ_LOCATION_REGEX,
				PluginConstants.CONFIG_PORT_READ_LOCATION_REGEX,
				"[^0-9]*([0-9]{3,5})[^0-9]?");
		paramPortReadLocation.setMinimumRequiredUserMode(
				StringParameter.MODE_INTERMEDIATE);

		paramPortReadLocation.addListener(param -> {
			String value = ((DirectoryParameter) param).getValue();
			paramPortReadLocationRegEx.setEnabled(!value.isEmpty());
		});
		paramPortReadLocationRegEx.setEnabled(
				!paramPortReadLocation.getValue().isEmpty());

		tabFolder = configModel.createTabFolder();
	}

	/* (non-Javadoc)
	 * @see com.biglybt.pif.UnloadablePlugin#unload()
	 */
	@Override
	public void unload()
			throws PluginException {

		if (pi != null) {
			UIManager uiManager = pi.getUIManager();
			if (uiManager != null) {
				uiManager.removeUIListener(this);
			}
			pi.removeListener(this);
		}

		if (ui != null) {
			ui.destroy();
			ui = null;
		}

		if (configModel != null) {
			configModel.destroy();
		}
		if (model != null) {
			model.destroy();
		}

		if (checker != null) {
			checker.destroy();
			checker = null;
		}

		listeners.clear();
	}

	/* (non-Javadoc)
	 * @see com.biglybt.pif.PluginListener#initializationComplete()
	 */
	@Override
	public void initializationComplete() {
		pi.getUtilities().createThread("FirstVPNCheck", new AERunnable() {
			@Override
			public void runSupport() {
				if (checker == null) {
					return;
				}
				try {
					checker.portBindingCheck();
					checker.calcProtocolAddresses();
				} catch (Throwable t) {
					t.printStackTrace();
				}
				checker.buildTimer();
			}
		});
	}

	/* (non-Javadoc)
	 * @see com.biglybt.pif.PluginListener#closedownInitiated()
	 */
	@Override
	public void closedownInitiated() {
	}

	/* (non-Javadoc)
	 * @see com.biglybt.pif.PluginListener#closedownComplete()
	 */
	@Override
	public void closedownComplete() {
	}

	/* (non-Javadoc)
	 * @see com.biglybt.pif.ui.UIManagerListener#UIDetached(com.biglybt.pif.ui.UIInstance)
	 */
	@Override
	public void UIDetached(UIInstance instance) {
		if (instance instanceof UISWTInstance) {
			if (ui != null) {
				ui.destroy();
				ui = null;
			}
			uiInstance = null;
		}
	}

	/* (non-Javadoc)
	 * @see com.biglybt.pif.ui.UIManagerListener#UIAttached(com.biglybt.pif.ui.UIInstance)
	 */
	@Override
	public void UIAttached(UIInstance instance) {
		if (instance instanceof UISWTInstance) {
			UISWTInstance swtInstance = (UISWTInstance) instance;
			ui = new UI(pi, swtInstance);
		}
		uiInstance = instance;
	}

	public static void log(String s) {
		if (s == null) {
			return;
		}
		if (s.endsWith("\n")) {
			s = s.substring(0, s.length() - 1);
		}
		if (LOG_TO_STDOUT || logger == null) {
			long offsetTime = System.currentTimeMillis() - initializedOn;
			System.out.println(offsetTime + "] LOGGER: " + s);
		}
		if (logger == null) {
			return;
		}
		logger.log(s);
	}

	public final void addListener(CheckerListener l) {
		listeners.add(l);
		try {
			if (checker != null) {
				l.portCheckStatusChanged(checker.lastPortCheckStatus);
				l.protocolAddressesStatusChanged(checker.lastProtocolAddresses);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public final void removeListener(CheckerListener l) {
		listeners.remove(l);
	}

	public CheckerListener[] getCheckerListeners() {
		return listeners.toArray(new CheckerListener[0]);
	}
}
