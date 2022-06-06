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

import java.util.Locale;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import com.biglybt.ui.UIFunctionsManager;
import com.biglybt.ui.common.viewtitleinfo.ViewTitleInfo;
import com.biglybt.ui.mdi.MdiEntry;
import com.biglybt.ui.mdi.MdiEntryCreationListener;
import com.biglybt.ui.mdi.MultipleDocumentInterface;
import com.biglybt.ui.swt.pif.UISWTInstance;
import com.biglybt.ui.swt.skin.SWTSkinFactory;
import com.biglybt.ui.swt.skin.SWTSkinProperties;
import com.vuze.plugin.azVPN_Helper.CheckerCommon.Status;

import com.biglybt.pif.PluginInterface;
import com.biglybt.pif.ui.UIInstance;
import com.biglybt.pif.ui.UIManager;
import com.biglybt.pif.ui.menus.MenuItem;
import com.biglybt.pif.ui.menus.MenuItemListener;
import com.biglybt.pif.ui.menus.MenuManager;
import com.biglybt.pif.utils.LocaleUtilities;

public class UI
	implements MdiEntryCreationListener, CheckerListener
{

	public static final String VIEW_ID = "VPNHelper_View";

	private PluginInterface pi;

	private MenuItem menuItemShowView;

	private MdiEntry mdiEntry;

	public UI(PluginInterface pi, UISWTInstance swtInstance) {
		this.pi = pi;

		addSkinPaths();

		MultipleDocumentInterface mdi = UIFunctionsManager.getUIFunctions().getMDI();

		mdi.registerEntry(VIEW_ID, this);

		// Requires 4700
		mdi.loadEntryByID(VIEW_ID, false, true, null);

		UIManager uiManager = pi.getUIManager();
		menuItemShowView = uiManager.getMenuManager().addMenuItem(
				MenuManager.MENU_MENUBAR,
				"ConfigView.section." + PluginConstants.CONFIG_SECTION_ID);
		menuItemShowView.setDisposeWithUIDetach(UIInstance.UIT_SWT);
		menuItemShowView.addListener(new MenuItemListener() {

			@Override
			public void selected(MenuItem menu, Object target) {
				MultipleDocumentInterface mdi = UIFunctionsManager.getUIFunctions().getMDI();
				mdi.showEntryByID(UI.VIEW_ID);
			}
		});

		PluginVPNHelper.instance.addListener(this);

		//swtInstance.addView(UISWTInstance.VIEW_MAIN, VIEW_ID, view.class, swtInstance);
	}

	public void destroy() {
		if (menuItemShowView != null) {
			menuItemShowView.remove();
			menuItemShowView = null;
		}
		
		MultipleDocumentInterface mdi = UIFunctionsManager.getUIFunctions().getMDI();

		mdi.deregisterEntry(VIEW_ID, this);
		
		if ( mdiEntry != null ){
			mdi.closeEntry(mdiEntry, false);
			mdiEntry = null;
		}
	}

	/* (non-Javadoc)
	 * @see MdiEntryCreationListener#createMDiEntry(java.lang.String)
	 */
	@Override
	public MdiEntry createMDiEntry(String id) {
		final MultipleDocumentInterface mdi = UIFunctionsManager.getUIFunctions().getMDI();
		mdiEntry = mdi.createEntryFromSkinRef(null, VIEW_ID, "vpnhelperview",
				"VPNHelper", null, null, true, null);
		mdiEntry.setTitleID("vpnhelper.sidebar.title");

		ViewTitleInfo viewTitleInfo = new ViewTitleInfo() {
			@Override
			public Object getTitleInfoProperty(int propertyID) {
				if (propertyID == ViewTitleInfo.TITLE_INDICATOR_TEXT) {
					Status status = PluginVPNHelper.instance.checker == null
							? new Status(CheckerCommon.STATUS_ID_WARN)
							: PluginVPNHelper.instance.checker.getCurrentStatus();

					LocaleUtilities texts = UI.this.pi.getUtilities().getLocaleUtilities();
					String indicatorKey = status.getIndicatorKey();
					if (indicatorKey != null) {
						return texts.getLocalisedMessageText(indicatorKey);
					}
					return null;
				}
				if (propertyID == ViewTitleInfo.TITLE_INDICATOR_TEXT_TOOLTIP) {
					Status status = PluginVPNHelper.instance.checker == null
							? new Status(CheckerCommon.STATUS_ID_WARN)
							: PluginVPNHelper.instance.checker.getCurrentStatus();

					LocaleUtilities texts = UI.this.pi.getUtilities().getLocaleUtilities();

					String indicatorTooltipKey = status.getIndicatorTooltipKey();
					if (indicatorTooltipKey != null
							&& (texts.hasLocalisedMessageText(indicatorTooltipKey)
									|| (indicatorTooltipKey.startsWith("!")
											&& indicatorTooltipKey.endsWith("!")))) {
						return texts.getLocalisedMessageText(indicatorTooltipKey);
					}
					return null;
				}
				if (propertyID == ViewTitleInfo.TITLE_TEXT) {
//					LocaleUtilities texts = UI.this.pif.getUtilities().getLocaleUtilities();
//					return texts.getLocalisedMessageText(
//							"ConfigView.section." + PluginConstants.CONFIG_SECTION_ID);
				}
				if (propertyID == ViewTitleInfo.TITLE_INDICATOR_COLOR) {
					int statusID = PluginVPNHelper.instance.checker == null
							? CheckerCommon.STATUS_ID_WARN
							: PluginVPNHelper.instance.checker.getCurrentStatus().statusID;

					if (statusID == CheckerCommon.STATUS_ID_OK) {
						return new int[] {
							0,
							80,
							0
						};
					}
					if (statusID == CheckerCommon.STATUS_ID_BAD) {
						return new int[] {
							128,
							30,
							30
						};
					}
					if (statusID == CheckerCommon.STATUS_ID_WARN) {
						return new int[] {
							255,
							140,
							0
						};
					}
					return null;
				}
				return null;
			}
		};

		mdiEntry.setViewTitleInfo(viewTitleInfo);

		return mdiEntry;
	}

	private void addSkinPaths() {
		String path = "com/vuze/plugin/azVPN_Helper/skins/";

		String sFile = path + "skin3_" + PluginConstants.CONFIG_SECTION_ID;

		ClassLoader loader = PluginVPNHelper.class.getClassLoader();

		SWTSkinProperties skinProperties = SWTSkinFactory.getInstance().getSkinProperties();

		try {
			ResourceBundle subBundle = ResourceBundle.getBundle(sFile,
					Locale.getDefault(), loader);

			skinProperties.addResourceBundle(subBundle, path, loader);

		} catch (MissingResourceException mre) {

			mre.printStackTrace();
		}
	}

	@Override
	public void protocolAddressesStatusChanged(String status) {
	}

	@Override
	public void portCheckStatusChanged(String status) {
		if (mdiEntry != null) {
			mdiEntry.redraw();
		}
	}

	@Override
	public void portCheckStart() {
	}

	@Override
	public void checkerChanged(CheckerCommon checker) {
		if (mdiEntry != null) {
			mdiEntry.redraw();
		}
	}
}
