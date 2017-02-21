package upsc.api.test;

import android.util.Log;
import upsc.framework.api.UpscSIM;
import upsc.framework.api.Information;

public class API_GetInfo extends UPSCTestCase{
	
	private static final String LOG_TAG = "API_GetInfo";
	
	public void testGetInfo() throws Exception{
		Information info = m_upsc.getInfo();
		Log.i(LOG_TAG, info.getString());
	}
}
