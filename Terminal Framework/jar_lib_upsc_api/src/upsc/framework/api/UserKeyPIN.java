package upsc.framework.api;


import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

class UserKeyPIN{
	static final int LENGTH_MAX = 4;
	private static final String LOG_TAG = "UserKeyPIN";
	
	static byte[] getFromUser(Context ctx){
		Log.i(LOG_TAG, "Enter getFromUser()");
		
		/*
		Intent intent = new Intent(ctx, ActivityUserPIN.class);
		intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
		ctx.startActivity(intent);
		*/
		
		byte[] keyPIN = {0x02, 0x02, 0x02, 0x02};
		
		Log.i(LOG_TAG, "Leave getFromUser()");
		return keyPIN;
	}
}
